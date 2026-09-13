#include <node_api.h>
#include <abstraction/ipc/client.h>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <memory>
#include <string>
#include <vector>

namespace {
using Clock=std::chrono::steady_clock;
constexpr size_t frame_bound=2*1024*1024;
constexpr napi_type_tag token_tag{0x17ef51e23509bad1ULL,0xbe22908c1635cf98ULL};
std::atomic<unsigned> active{0};
struct Signal {
  oa_ipc_cancellation* value=nullptr;
  // Accessed only on the owning JavaScript thread. Workers only use value.
  std::vector<napi_async_work> queued;
  ~Signal(){oa_ipc_cancellation_release(value);}
};
using Token=std::shared_ptr<Signal>;
struct Work {
  napi_async_work work=nullptr;
  napi_deferred deferred=nullptr;
  std::string endpoint,principal,program;
  uint32_t principal_kind=0;
  std::vector<unsigned char> request,response;
  Token signal;
  Clock::time_point deadline;
  size_t limit=0,transferred=0;
  bool reply=false;
  int status=OA_IPC_OK;
  const char* stage="open";
};
void checked(napi_status s){if(s!=napi_ok)throw s;}
napi_value fail(napi_env env,const char* message){napi_throw_error(env,nullptr,message);return nullptr;}
Token token(napi_env env,napi_value value){
  bool tagged=false;checked(napi_check_object_type_tag(env,value,&token_tag,&tagged));
  if(!tagged)throw napi_invalid_arg;
  void* p=nullptr;checked(napi_unwrap(env,value,&p));
  if(!p)throw napi_invalid_arg;
  return *static_cast<Token*>(p);
}
napi_value create_signal(napi_env env,napi_callback_info){try{
  auto signal=std::make_shared<Signal>();
  if(oa_ipc_cancellation_create(&signal->value)!=OA_IPC_OK)return fail(env,"cancellation allocation failed");
  napi_value result;checked(napi_create_object(env,&result));
  checked(napi_type_tag_object(env,result,&token_tag));
  auto holder=std::make_unique<Token>(signal);
  checked(napi_wrap(env,result,holder.get(),[](napi_env,void* p,void*){delete static_cast<Token*>(p);},nullptr,nullptr));
  holder.release();return result;
}catch(...){return fail(env,"invalid cancellation creation");}}
napi_value cancel(napi_env env,napi_callback_info info){try{
  size_t n=1;napi_value args[1];checked(napi_get_cb_info(env,info,&n,args,nullptr,nullptr));
  if(n!=1)throw napi_invalid_arg;
  auto signal=token(env,args[0]);
  oa_ipc_cancellation_signal(signal->value);
  for(auto work:signal->queued)napi_cancel_async_work(env,work);
  napi_value result;checked(napi_get_undefined(env,&result));return result;
}catch(...){return fail(env,"invalid cancellation token");}}
napi_value bootstrap(napi_env env,napi_callback_info){try{
  for(int attempt=0;attempt<3;++attempt){
    size_t size=0;int status=oa_ipc_runtime_endpoint(nullptr,0,&size);
    if(status!=OA_IPC_OK||size==0||size>4096)return fail(env,"native bootstrap unavailable");
    std::vector<char> bytes(size);status=oa_ipc_runtime_endpoint(bytes.data(),bytes.size(),&size);
    if(status==OA_IPC_INVALID_ARGUMENT&&size>bytes.size())continue;
    if(status!=OA_IPC_OK||size==0||size>bytes.size())return fail(env,"native bootstrap unavailable");
    napi_value result;checked(napi_create_string_utf8(env,bytes.data(),size-1,&result));return result;
  }return fail(env,"native bootstrap changed repeatedly");
}catch(...){return fail(env,"native bootstrap failed");}}
bool read_exact(Work& w,oa_ipc_connection* connection,unsigned char* out,size_t size){
  size_t got=0;
  while(got<size){size_t n=0;w.status=oa_ipc_read(connection,out+got,size-got,&n);
    if(w.status!=OA_IPC_OK){w.transferred=got;return false;}
    if(n==0||n>size-got){w.status=OA_IPC_INTERNAL_ERROR;return false;}got+=n;
  }return true;
}
void execute(napi_env,void* p){
  auto& w=*static_cast<Work*>(p);
  try{
    auto left=w.deadline-Clock::now();
    if(left<=Clock::duration::zero()){w.status=OA_IPC_TIMEOUT;return;}
    auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(left).count();
    oa_ipc_connection* raw=nullptr;
    if(w.principal_kind){
      const oa_ipc_server_expectation expected{sizeof(oa_ipc_server_expectation),1,w.principal_kind,0,
        w.principal.data(),w.principal.size(),w.program.data(),w.program.size()};
      w.status=oa_ipc_open_verified(w.endpoint.data(),w.endpoint.size(),static_cast<uint32_t>(ms),w.signal?w.signal->value:nullptr,&expected,&raw);
    }else w.status=oa_ipc_open_cancelable(w.endpoint.data(),w.endpoint.size(),static_cast<uint32_t>(ms),w.signal?w.signal->value:nullptr,&raw);
    if(w.status!=OA_IPC_OK)return;
    std::unique_ptr<oa_ipc_connection,decltype(&oa_ipc_close)> connection(raw,oa_ipc_close);
    w.stage="write";
    w.status=oa_ipc_write(raw,w.request.data(),w.request.size(),&w.transferred);
    if(w.status!=OA_IPC_OK)return;
    if(w.transferred!=w.request.size()){w.status=OA_IPC_INTERNAL_ERROR;return;}
    w.stage="read";w.transferred=0;
    if(!w.reply){unsigned char byte;size_t n=0;w.status=oa_ipc_read(raw,&byte,1,&n);
      if(w.status==OA_IPC_DISCONNECTED)w.status=OA_IPC_OK;
      else if(w.status==OA_IPC_OK)w.status=OA_IPC_IO_ERROR;
      return;
    }
    unsigned char prefix[4];if(!read_exact(w,raw,prefix,4))return;
    size_t size=(size_t(prefix[0])<<24)|(size_t(prefix[1])<<16)|(size_t(prefix[2])<<8)|prefix[3];
    if(size>w.limit){w.status=OA_IPC_INVALID_ARGUMENT;w.stage="frame_limit";return;}
    w.response.resize(size);read_exact(w,raw,w.response.data(),size);
  }catch(const std::bad_alloc&){w.status=OA_IPC_NO_MEMORY;}catch(...){w.status=OA_IPC_INTERNAL_ERROR;}
}
void complete(napi_env env,napi_status status,void* p){
  std::unique_ptr<Work> w(static_cast<Work*>(p));
  if(w->signal){auto& q=w->signal->queued;q.erase(std::remove(q.begin(),q.end(),w->work),q.end());}
  active.fetch_sub(1);
  if(status!=napi_ok&&w->status==OA_IPC_OK)w->status=OA_IPC_CANCELLED;
  napi_value result;
  if(w->status==OA_IPC_OK){
    if(w->reply)status=napi_create_buffer_copy(env,w->response.size(),w->response.data(),nullptr,&result);
    else status=napi_get_undefined(env,&result);
    if(status==napi_ok)napi_resolve_deferred(env,w->deferred,result);
  }else{
    napi_value message,field;
    if(napi_create_string_utf8(env,w->stage,NAPI_AUTO_LENGTH,&message)==napi_ok&&napi_create_error(env,nullptr,message,&result)==napi_ok){
      napi_create_int32(env,w->status,&field);napi_set_named_property(env,result,"status",field);
      napi_create_double(env,double(w->transferred),&field);napi_set_named_property(env,result,"transferred",field);
      napi_reject_deferred(env,w->deferred,result);
    }
  }
  napi_delete_async_work(env,w->work);
}
napi_value call(napi_env env,napi_callback_info info){
  bool counted=false;
  std::unique_ptr<Work> w;
  try{
    size_t n=7;napi_value args[7];checked(napi_get_cb_info(env,info,&n,args,nullptr,nullptr));
    if(n!=6&&n!=7)throw napi_invalid_arg;
    w=std::make_unique<Work>();size_t length=0;
    checked(napi_get_value_string_utf8(env,args[0],nullptr,0,&length));
    if(length==0||length>4096)throw napi_invalid_arg;
    std::vector<char> endpoint(length+1);checked(napi_get_value_string_utf8(env,args[0],endpoint.data(),endpoint.size(),&length));
    w->endpoint.assign(endpoint.data(),length);if(w->endpoint.find('\0')!=std::string::npos)throw napi_invalid_arg;
    napi_typedarray_type kind;size_t bytes=0;void* data=nullptr;napi_value arraybuffer;size_t offset;
    checked(napi_get_typedarray_info(env,args[1],&kind,&bytes,&data,&arraybuffer,&offset));
    if(kind!=napi_uint8_array&&kind!=napi_uint8_clamped_array)throw napi_invalid_arg;
    double timeout,limit;checked(napi_get_value_double(env,args[2],&timeout));checked(napi_get_value_double(env,args[4],&limit));
    if(!std::isfinite(timeout)||timeout<0||timeout>UINT32_MAX||!std::isfinite(limit)||limit<1||limit>frame_bound||std::floor(limit)!=limit||bytes>limit)throw napi_invalid_arg;
    w->deadline=Clock::now()+std::chrono::milliseconds(static_cast<uint32_t>(timeout));w->limit=static_cast<size_t>(limit);
    napi_valuetype type;checked(napi_typeof(env,args[3],&type));if(type!=napi_null&&type!=napi_undefined)w->signal=token(env,args[3]);
    checked(napi_get_value_bool(env,args[5],&w->reply));
    if(n==7){
      checked(napi_typeof(env,args[6],&type));
      if(type!=napi_null&&type!=napi_undefined){
        napi_value field;double kind_value;
        checked(napi_get_named_property(env,args[6],"principalKind",&field));checked(napi_get_value_double(env,field,&kind_value));
        if(kind_value!=1&&kind_value!=2)throw napi_invalid_arg;w->principal_kind=static_cast<uint32_t>(kind_value);
        auto text=[&](const char* name){napi_value value;checked(napi_get_named_property(env,args[6],name,&value));size_t size=0;checked(napi_get_value_string_utf8(env,value,nullptr,0,&size));
          if(size==0||size>65536)throw napi_invalid_arg;std::vector<char> buffer(size+1);checked(napi_get_value_string_utf8(env,value,buffer.data(),buffer.size(),&size));std::string result(buffer.data(),size);if(result.find('\0')!=std::string::npos)throw napi_invalid_arg;return result;};
        w->principal=text("principal");w->program=text("program");
      }
    }
    w->request.resize(bytes+4);for(int i=0;i<4;++i)w->request[i]=static_cast<unsigned char>(bytes>>(24-8*i));
    if(bytes)std::copy_n(static_cast<unsigned char*>(data),bytes,w->request.begin()+4);
    unsigned previous=active.fetch_add(1);counted=true;
    if(previous>=32)throw napi_queue_full;
    napi_value promise,name;checked(napi_create_promise(env,&w->deferred,&promise));checked(napi_create_string_utf8(env,"oa.ipc",NAPI_AUTO_LENGTH,&name));
    checked(napi_create_async_work(env,nullptr,name,execute,complete,w.get(),&w->work));
    if(w->signal)w->signal->queued.push_back(w->work);
    checked(napi_queue_async_work(env,w->work));w.release();return promise;
  }catch(...){
    if(w&&w->work){
      if(w->signal){auto& q=w->signal->queued;q.erase(std::remove(q.begin(),q.end(),w->work),q.end());}
      napi_delete_async_work(env,w->work);
    }
    if(counted)active.fetch_sub(1);return fail(env,"invalid or over-capacity IPC call");
  }
}
napi_value init(napi_env env,napi_value exports){
  if(oa_ipc_version()!=1)return fail(env,"unsupported IPC ABI version");
  napi_property_descriptor methods[]={
    {"call",nullptr,call,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"createCancellation",nullptr,create_signal,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"cancel",nullptr,cancel,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"runtimeEndpoint",nullptr,bootstrap,nullptr,nullptr,nullptr,napi_default,nullptr}};
  if(napi_define_properties(env,exports,4,methods)!=napi_ok)return nullptr;return exports;
}
}
NAPI_MODULE(NODE_GYP_MODULE_NAME,init)
