#include <node_api.h>
#include <abstraction/ipc/client.h>
#include <abstraction/ipc/constants/rec.h>
#ifdef _WIN32
#include "path_identity_windows.h"
#endif
#include <atomic>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {
using Clock=std::chrono::steady_clock;
// The largest maximum frame a client binding accepts (identity.thrift, IPC-F1).
constexpr size_t frame_bound=static_cast<size_t>(abstraction::ipc::constants::kIpcClientMaxFrame);
constexpr napi_type_tag token_tag{0x17ef51e23509bad1ULL,0xbe22908c1635cf98ULL};
std::atomic<unsigned> active{0};
struct Signal {
  oa_ipc_cancellation* value=nullptr;
  ~Signal(){oa_ipc_cancellation_release(value);}
};
using Token=std::shared_ptr<Signal>;
struct Work {
  napi_deferred deferred=nullptr;
  std::string endpoint,principal,program;
  uint32_t principal_kind=0;
  std::vector<unsigned char> request,response;
  Token signal;
  Clock::time_point deadline;
  size_t limit=0,transferred=0;
  bool reply=false,sessions=false;
  int status=OA_IPC_OK;
  const char* stage="open";
};
void checked(napi_status s){if(s!=napi_ok)throw s;}
// Each blocking native operation runs on a thread of its own, never on the
// runtime's shared worker pool (libuv's four threads by default): a waiting
// call such as a 30 s observe or wait would hold a pool thread, and a short
// call queued behind four of them reached the native library after its own
// deadline and failed before its exchange (an adopter's Node host,
// 2026-11-01: title calls refused at stage "open"). A call's deadline counts
// from the moment it is made. The 32-call cap bounds the threads.
//
// A Flight is one such call. Its result returns to the JavaScript thread
// through a thread-safe function. Its environment may end first: a Worker is
// terminated, a renderer closes. Node then frees the thread-safe function
// while the call's thread still runs, and a later call into it reads freed
// memory (review 2026-11-01: exit 139 when a Worker with four calls in flight
// was terminated). So each flight registers an environment cleanup hook after
// its thread-safe function; Node runs cleanup hooks in reverse order of
// registration, so the hook runs while the function is still alive. The hook
// marks the flight closing, signals its cancellation and waits for its thread.
// The thread touches the thread-safe function only under the flight's lock
// and only while the flight is not closing. Ownership of the job is decided
// under that lock: posted (delivery, or the function's teardown, frees it) or
// abandoned (the hook frees it).
struct Completion {
  void (*complete)(napi_env,napi_status,void*);
  void (*drop)(void*);
};
struct Flight {
  std::mutex m;
  std::condition_variable cv;
  enum {Running,Posted,Abandoned} state=Running;
  bool closing=false;
  napi_threadsafe_function done=nullptr;
  void* job=nullptr;
  const Completion* completion=nullptr;
  // The call's cancellation: the caller's token, or one of its own.
  std::shared_ptr<Signal> signal;
  // The cleanup hook's registered argument while the hook is registered.
  std::shared_ptr<Flight>* hook=nullptr;
};
using FlightRef=std::shared_ptr<Flight>;
void flight_hook(void* arg){
  std::unique_ptr<FlightRef> ref(static_cast<FlightRef*>(arg));
  FlightRef f=*ref;
  std::unique_lock<std::mutex> lock(f->m);
  f->closing=true;f->hook=nullptr;
  if(f->state==Flight::Running){
    oa_ipc_cancellation_signal(f->signal->value);
    f->cv.wait(lock,[&]{return f->state!=Flight::Running;});
  }
  // A posted job is freed by delivery, which the function's teardown makes
  // with no environment.
  if(f->state==Flight::Abandoned){lock.unlock();f->completion->drop(f->job);}
}
void deliver(napi_env env,napi_value,void*,void* data){
  std::unique_ptr<FlightRef> ref(static_cast<FlightRef*>(data));
  FlightRef f=*ref;
  if(env==nullptr){f->completion->drop(f->job);return;}
  FlightRef* hook=nullptr;
  {std::lock_guard<std::mutex> lock(f->m);hook=f->hook;f->hook=nullptr;}
  if(hook){napi_remove_env_cleanup_hook(env,flight_hook,hook);delete hook;}
  f->completion->complete(env,napi_ok,f->job);
}
void finish(const FlightRef& f){
  std::lock_guard<std::mutex> lock(f->m);
  if(!f->closing){
    auto ref=std::make_unique<FlightRef>(f);
    if(napi_call_threadsafe_function(f->done,ref.get(),napi_tsfn_nonblocking)==napi_ok){
      ref.release();f->state=Flight::Posted;
    }else{
      f->state=Flight::Abandoned;
    }
    napi_release_threadsafe_function(f->done,napi_tsfn_release);
  }else{
    f->state=Flight::Abandoned;
  }
  f->cv.notify_all();
}
Token own_signal(){
  auto signal=std::make_shared<Signal>();
  if(oa_ipc_cancellation_create(&signal->value)!=OA_IPC_OK)throw napi_generic_failure;
  return signal;
}
template<class Job>
void dispatch(napi_env env,const char* label,const Completion& completion,Job* job,void (*run)(Job*)){
  if(!job->signal)job->signal=own_signal();
  auto f=std::make_shared<Flight>();
  f->job=job;f->completion=&completion;f->signal=job->signal;
  napi_value name;checked(napi_create_string_utf8(env,label,NAPI_AUTO_LENGTH,&name));
  checked(napi_create_threadsafe_function(env,nullptr,nullptr,name,0,1,nullptr,nullptr,nullptr,deliver,&f->done));
  auto hook=std::make_unique<FlightRef>(f);
  if(napi_add_env_cleanup_hook(env,flight_hook,hook.get())!=napi_ok){
    napi_release_threadsafe_function(f->done,napi_tsfn_abort);
    throw napi_generic_failure;
  }
  f->hook=hook.get();
  try{
    std::thread([f,job,run]{run(job);finish(f);}).detach();
  }catch(...){
    napi_remove_env_cleanup_hook(env,flight_hook,hook.get());
    napi_release_threadsafe_function(f->done,napi_tsfn_abort);
    throw;
  }
  hook.release();
}
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
napi_value features(napi_env env,napi_callback_info){
  napi_value result;if(napi_create_uint32(env,oa_ipc_features(),&result)!=napi_ok)return nullptr;return result;
}
void execute(napi_env,void* p){
  auto& w=*static_cast<Work*>(p);
  try{
    auto left=w.deadline-Clock::now();
    if(left<=Clock::duration::zero()){w.status=OA_IPC_TIMEOUT;return;}
    auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(left).count();
    if(w.endpoint.compare(0,4,"xpc:")==0 && !(oa_ipc_features() & OA_IPC_FEATURE_XPC)){
      w.status=OA_IPC_PROOF_UNAVAILABLE;return;
    }
    const bool single=!w.sessions&&w.endpoint.compare(0,4,"xpc:")!=0;
    const bool report_open=w.endpoint.compare(0,4,"xpc:")!=0&&(oa_ipc_features()&OA_IPC_FEATURE_OPEN_FAILURE);
    if(single && !(oa_ipc_features() & OA_IPC_FEATURE_SINGLE_EXCHANGE)){
      w.status=OA_IPC_PROOF_UNAVAILABLE;return;
    }
    {
      // The shared owner selects fresh single exchange, session pooling or XPC.
      const oa_ipc_server_expectation expected{sizeof(oa_ipc_server_expectation),1,w.principal_kind,0,
        w.principal.data(),w.principal.size(),w.program.data(),w.program.size()};
      oa_ipc_reply* answer=nullptr;
      w.stage="exchange";
      w.status=oa_ipc_session_call(w.endpoint.data(),w.endpoint.size(),static_cast<uint32_t>(ms),w.signal?w.signal->value:nullptr,
        w.principal_kind?&expected:nullptr,w.request.data(),w.request.size(),static_cast<uint32_t>(w.limit),
        (w.reply?0:OA_IPC_CALL_ONE_WAY)|(single?OA_IPC_CALL_SINGLE_EXCHANGE:0)|(report_open?OA_IPC_CALL_REPORT_OPEN_FAILURE:0),&answer,&w.transferred);
      std::unique_ptr<oa_ipc_reply,decltype(&oa_ipc_reply_release)> owned(answer,oa_ipc_reply_release);
      if(w.status==OA_IPC_OK&&w.reply){size_t n=0;const auto* data=oa_ipc_reply_data(answer,&n);if(n)w.response.assign(data,data+n);}
      if(w.status==OA_IPC_INVALID_ARGUMENT)w.stage="frame_limit";
      return;
    }
  }catch(const std::bad_alloc&){w.status=OA_IPC_NO_MEMORY;}catch(...){w.status=OA_IPC_INTERNAL_ERROR;}
}
void complete(napi_env env,napi_status status,void* p){
  std::unique_ptr<Work> w(static_cast<Work*>(p));
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
}
void run_call(Work* w){execute(nullptr,w);}
void drop_call(void* p){delete static_cast<Work*>(p);active.fetch_sub(1);}
const Completion call_completion{complete,drop_call};
napi_value call(napi_env env,napi_callback_info info){
  bool counted=false;
  std::unique_ptr<Work> w;
  try{
    size_t n=8;napi_value args[8];checked(napi_get_cb_info(env,info,&n,args,nullptr,nullptr));
    if(n<6||n>8)throw napi_invalid_arg;
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
    if(n==8){
      checked(napi_typeof(env,args[7],&type));
      if(type!=napi_undefined)checked(napi_get_value_bool(env,args[7],&w->sessions));
    }
    if(n>=7){
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
    if(bytes)w->request.assign(static_cast<unsigned char*>(data),static_cast<unsigned char*>(data)+bytes);
    unsigned previous=active.fetch_add(1);counted=true;
    if(previous>=32)throw napi_queue_full;
    napi_value promise;checked(napi_create_promise(env,&w->deferred,&promise));
    dispatch(env,"oa.ipc",call_completion,w.get(),run_call);w.release();return promise;
  }catch(...){
    if(counted)active.fetch_sub(1);return fail(env,"invalid or over-capacity IPC call");
  }
}
// Installed runtime selection through the shared selector, off the JavaScript
// thread: Linux queries the user manager, which may take the whole budget.
struct Selection {
  napi_deferred deferred=nullptr;
  Token signal;
  uint32_t timeout=0;
  int status=OA_IPC_OK;
  uint32_t kind=0;
  std::string principal,program;
  bool activation=false;
  int32_t outcome=OA_IPC_ACTIVATION_NONE;
  Clock::time_point deadline;
};
void select_execute(napi_env,void* p){
  auto& s=*static_cast<Selection*>(p);
  try{
    if(s.activation){
      auto left=s.deadline-Clock::now();
      if(left<=Clock::duration::zero()){s.status=OA_IPC_TIMEOUT;return;}
      if(!(oa_ipc_features()&OA_IPC_FEATURE_RUNTIME_ACTIVATION)){s.status=OA_IPC_PROOF_UNAVAILABLE;return;}
      auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(left).count();
      oa_ipc_server_expectation expected{sizeof(oa_ipc_server_expectation),1,s.kind,0,
        s.principal.data(),s.principal.size(),s.program.data(),s.program.size()};
      s.status=oa_ipc_activate_runtime(&expected,static_cast<uint32_t>(std::min<int64_t>(UINT32_MAX,std::max<int64_t>(1,ms))),
        s.signal?s.signal->value:nullptr,&s.outcome);
      if(s.status==OA_IPC_OK&&(s.outcome<OA_IPC_ACTIVATION_REQUEST_COMPLETED||s.outcome>OA_IPC_ACTIVATION_REFUSED))s.status=OA_IPC_INTERNAL_ERROR;
      if(s.status==OA_IPC_OK&&Clock::now()>=s.deadline)s.status=OA_IPC_TIMEOUT;
      return;
    }
    oa_ipc_runtime_selection* raw=nullptr;
    s.status=oa_ipc_select_runtime(s.timeout,s.signal?s.signal->value:nullptr,&raw);
    if(s.status!=OA_IPC_OK)return;
    if(!raw){s.status=OA_IPC_INTERNAL_ERROR;return;}
    std::unique_ptr<oa_ipc_runtime_selection,decltype(&oa_ipc_runtime_selection_release)> owned(raw,oa_ipc_runtime_selection_release);
    const auto* e=oa_ipc_selected_server(raw);
    if(!e||e->struct_size!=sizeof(oa_ipc_server_expectation)||e->version!=1||e->reserved||
        (e->principal_kind!=OA_IPC_PRINCIPAL_WINDOWS_SID&&e->principal_kind!=OA_IPC_PRINCIPAL_POSIX_UID)||
        !e->principal||!e->program||e->principal_length==0||e->principal_length>65536||
        e->program_length==0||e->program_length>65536){s.status=OA_IPC_INTERNAL_ERROR;return;}
    s.kind=e->principal_kind;s.principal.assign(e->principal,e->principal_length);s.program.assign(e->program,e->program_length);
    if(s.principal.find('\0')!=std::string::npos||s.program.find('\0')!=std::string::npos)s.status=OA_IPC_INTERNAL_ERROR;
  }catch(const std::bad_alloc&){s.status=OA_IPC_NO_MEMORY;}catch(...){s.status=OA_IPC_INTERNAL_ERROR;}
}
void select_complete(napi_env env,napi_status status,void* p){
  std::unique_ptr<Selection> s(static_cast<Selection*>(p));
  active.fetch_sub(1);
  if(status!=napi_ok&&s->status==OA_IPC_OK)s->status=OA_IPC_CANCELLED;
  napi_value result,field;
  if(s->activation&&s->status==OA_IPC_OK&&napi_create_int32(env,s->outcome,&result)==napi_ok){
    napi_resolve_deferred(env,s->deferred,result);
  }else if(!s->activation&&s->status==OA_IPC_OK&&napi_create_object(env,&result)==napi_ok&&
      napi_create_uint32(env,s->kind,&field)==napi_ok&&napi_set_named_property(env,result,"principalKind",field)==napi_ok&&
      napi_create_string_utf8(env,s->principal.data(),s->principal.size(),&field)==napi_ok&&napi_set_named_property(env,result,"principal",field)==napi_ok&&
      napi_create_string_utf8(env,s->program.data(),s->program.size(),&field)==napi_ok&&napi_set_named_property(env,result,"program",field)==napi_ok){
    napi_resolve_deferred(env,s->deferred,result);
  }else{
    if(s->status==OA_IPC_OK)s->status=OA_IPC_INTERNAL_ERROR;
    napi_value message;
    if(napi_create_string_utf8(env,"select",NAPI_AUTO_LENGTH,&message)==napi_ok&&napi_create_error(env,nullptr,message,&result)==napi_ok){
      napi_create_int32(env,s->status,&field);napi_set_named_property(env,result,"status",field);
      napi_create_double(env,0,&field);napi_set_named_property(env,result,"transferred",field);
      napi_reject_deferred(env,s->deferred,result);
    }
  }
}
void run_selection(Selection* s){select_execute(nullptr,s);}
void drop_selection(void* p){delete static_cast<Selection*>(p);active.fetch_sub(1);}
const Completion selection_completion{select_complete,drop_selection};
napi_value activate_runtime(napi_env env,napi_callback_info info){
  bool counted=false;
  std::unique_ptr<Selection> s;
  try{
    size_t n=3;napi_value args[3];checked(napi_get_cb_info(env,info,&n,args,nullptr,nullptr));
    if(n!=3)throw napi_invalid_arg;
    s=std::make_unique<Selection>();s->activation=true;
    napi_value field;double kind,timeout;
    checked(napi_get_named_property(env,args[0],"principalKind",&field));checked(napi_get_value_double(env,field,&kind));
    if(kind!=1&&kind!=2)throw napi_invalid_arg;s->kind=static_cast<uint32_t>(kind);
    auto text=[&](const char* name){napi_value value;checked(napi_get_named_property(env,args[0],name,&value));size_t size=0;
      checked(napi_get_value_string_utf8(env,value,nullptr,0,&size));if(size==0||size>65536)throw napi_invalid_arg;
      std::vector<char> bytes(size+1);checked(napi_get_value_string_utf8(env,value,bytes.data(),bytes.size(),&size));
      std::string value_text(bytes.data(),size);if(value_text.find('\0')!=std::string::npos)throw napi_invalid_arg;return value_text;};
    s->principal=text("principal");s->program=text("program");
    checked(napi_get_value_double(env,args[1],&timeout));if(!std::isfinite(timeout)||timeout<0||timeout>UINT32_MAX)throw napi_invalid_arg;
    s->deadline=Clock::now()+std::chrono::milliseconds(static_cast<uint32_t>(timeout));
    napi_valuetype type;checked(napi_typeof(env,args[2],&type));if(type!=napi_null&&type!=napi_undefined)s->signal=token(env,args[2]);
    unsigned previous=active.fetch_add(1);counted=true;if(previous>=32)throw napi_queue_full;
    napi_value promise;checked(napi_create_promise(env,&s->deferred,&promise));
    dispatch(env,"oa.ipc.activate",selection_completion,s.get(),run_selection);s.release();return promise;
  }catch(...){
    if(counted)active.fetch_sub(1);return fail(env,"invalid or over-capacity runtime activation");
  }
}
napi_value select_runtime(napi_env env,napi_callback_info info){
  bool counted=false;
  std::unique_ptr<Selection> s;
  try{
    size_t n=2;napi_value args[2];checked(napi_get_cb_info(env,info,&n,args,nullptr,nullptr));
    if(n!=2)throw napi_invalid_arg;
    s=std::make_unique<Selection>();
    double timeout;checked(napi_get_value_double(env,args[0],&timeout));
    if(!std::isfinite(timeout)||timeout<0||timeout>UINT32_MAX)throw napi_invalid_arg;
    s->timeout=static_cast<uint32_t>(timeout);
    napi_valuetype type;checked(napi_typeof(env,args[1],&type));if(type!=napi_null&&type!=napi_undefined)s->signal=token(env,args[1]);
    unsigned previous=active.fetch_add(1);counted=true;
    if(previous>=32)throw napi_queue_full;
    napi_value promise;checked(napi_create_promise(env,&s->deferred,&promise));
    dispatch(env,"oa.ipc.select",selection_completion,s.get(),run_selection);s.release();return promise;
  }catch(...){
    if(counted)active.fetch_sub(1);return fail(env,"invalid or over-capacity runtime selection");
  }
}
#ifdef _WIN32
std::wstring path_argument(napi_env env,napi_value value){
  napi_valuetype type;checked(napi_typeof(env,value,&type));
  if(type!=napi_string)throw napi_invalid_arg;
  size_t length=0;checked(napi_get_value_string_utf16(env,value,nullptr,0,&length));
  if(length>32767)throw napi_invalid_arg;
  std::vector<char16_t> buffer(length+1);size_t copied=0;
  checked(napi_get_value_string_utf16(env,value,buffer.data(),buffer.size(),&copied));
  std::wstring result;result.reserve(copied);
  for(size_t i=0;i<copied;++i)result.push_back(static_cast<wchar_t>(buffer[i]));
  return result;
}
const char* path_error_code(DWORD code){
  switch(code){
    case ERROR_FILE_NOT_FOUND:case ERROR_PATH_NOT_FOUND:case ERROR_INVALID_DRIVE:return "ENOENT";
    case ERROR_ACCESS_DENIED:case ERROR_PRIVILEGE_NOT_HELD:return "EACCES";
    case ERROR_SHARING_VIOLATION:case ERROR_LOCK_VIOLATION:return "EBUSY";
    case ERROR_INVALID_NAME:case ERROR_INVALID_PARAMETER:return "EINVAL";
    default:return "ERR_PATH_IDENTITY";
  }
}
std::wstring path_error_message(const oa_identity_path::Failure& error){
  if(error.kind==oa_identity_path::FailureKind::not_local)
    return L"identity: path is not on a local drive";
  if(error.kind==oa_identity_path::FailureKind::invalid_argument)
    return L"identity: invalid path argument";
  std::wstring message=L"identity: "+error.operation+L" "+error.path+L" failed with Windows error "+std::to_wstring(error.code);
  wchar_t system_message[512]{};
  const DWORD size=::FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,nullptr,error.code,0,
      system_message,static_cast<DWORD>(std::size(system_message)),nullptr);
  if(size){
    std::wstring detail(system_message,size);
    while(!detail.empty()&&(detail.back()==L'\r'||detail.back()==L'\n'||detail.back()==L' '))detail.pop_back();
    if(!detail.empty())message+=L": "+detail;
  }
  return message;
}
napi_value throw_path_failure(napi_env env,const oa_identity_path::Failure& error){
  const auto message=path_error_message(error);
  napi_value text,result,code,win32;
  if(napi_create_string_utf16(env,reinterpret_cast<const char16_t*>(message.data()),message.size(),&text)!=napi_ok||
      napi_create_error(env,nullptr,text,&result)!=napi_ok)return fail(env,"path identity failed");
  const char* code_text=error.kind==oa_identity_path::FailureKind::not_local?"ERR_NOT_LOCAL_PATH":
      error.kind==oa_identity_path::FailureKind::invalid_argument?"ERR_INVALID_ARG_TYPE":path_error_code(error.code);
  if(napi_create_string_utf8(env,code_text,NAPI_AUTO_LENGTH,&code)==napi_ok)
    napi_set_named_property(env,result,"code",code);
  if(error.kind==oa_identity_path::FailureKind::system&&napi_create_uint32(env,error.code,&win32)==napi_ok)
    napi_set_named_property(env,result,"win32Code",win32);
  napi_throw(env,result);return nullptr;
}
napi_value within_path(napi_env env,napi_callback_info info){
  try{
    size_t n=2;napi_value args[2];checked(napi_get_cb_info(env,info,&n,args,nullptr,nullptr));
    if(n!=2)throw napi_invalid_arg;
    const auto path=path_argument(env,args[0]);
    const auto folder=path_argument(env,args[1]);
    napi_value result;checked(napi_get_boolean(env,oa_identity_path::within(path,folder),&result));return result;
  }catch(const oa_identity_path::Failure& error){return throw_path_failure(env,error);}
  catch(...){return fail(env,"invalid path containment arguments or native path failure");}
}
#endif
napi_value init(napi_env env,napi_value exports){
  if(oa_ipc_version()!=1)return fail(env,"unsupported IPC ABI version");
  napi_property_descriptor methods[]={
    {"call",nullptr,call,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"features",nullptr,features,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"createCancellation",nullptr,create_signal,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"cancel",nullptr,cancel,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"runtimeEndpoint",nullptr,bootstrap,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"selectRuntime",nullptr,select_runtime,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"activateRuntime",nullptr,activate_runtime,nullptr,nullptr,nullptr,napi_default,nullptr},
#ifdef _WIN32
    {"withinPath",nullptr,within_path,nullptr,nullptr,nullptr,napi_default,nullptr},
#endif
  };
  if(napi_define_properties(env,exports,sizeof(methods)/sizeof(methods[0]),methods)!=napi_ok)return nullptr;return exports;
}
}
NAPI_MODULE(NODE_GYP_MODULE_NAME,init)
