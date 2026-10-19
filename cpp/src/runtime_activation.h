#pragma once
#include "runtime_selection.h"
#include "server_guard.h"
#include <abstraction/ipc/bootstrap.hpp>
#include <abstraction/ipc/client.hpp>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

namespace abstraction::ipc_internal {

inline bool same_runtime(const RuntimeIdentity& a,const RuntimeIdentity& b) {
    return a.kind==b.kind && a.principal==b.principal && a.program==b.program;
}

// One finite installed-start recipe. Platform access is supplied by the same
// native owner; fixtures replace it without touching installed state.
template<class Environment>
oa_ipc_status activate_runtime_with(const RuntimeIdentity& expected,local_stream::Deadline deadline,
    local_stream::Cancellation* cancellation,int32_t& outcome,Environment& env) {
    outcome=OA_IPC_ACTIVATION_NONE;
    auto status=selection_budget(deadline,cancellation);if(status!=OA_IPC_OK)return status;
    status=env.ordinary(outcome);if(status!=OA_IPC_OK||outcome==OA_IPC_ACTIVATION_REFUSED)return status;
    RuntimeIdentity current;
    status=env.select(current,deadline,cancellation);if(status!=OA_IPC_OK)return status;
    if(!same_runtime(expected,current))return OA_IPC_UNTRUSTED;
    auto held=env.hold(current.program);
    if(!held)return OA_IPC_UNTRUSTED;
    status=selection_budget(deadline,cancellation);if(status!=OA_IPC_OK)return status;
    bool absent=false;
    status=env.absent(absent);if(status!=OA_IPC_OK)return status;
    status=selection_budget(deadline,cancellation);if(status!=OA_IPC_OK)return status;
    if(!absent){outcome=OA_IPC_ACTIVATION_ENDPOINT_PRESENT;return OA_IPC_OK;}
    RuntimeIdentity before;
    status=env.select(before,deadline,cancellation);if(status!=OA_IPC_OK)return status;
    status=env.ordinary(outcome);if(status!=OA_IPC_OK||outcome==OA_IPC_ACTIVATION_REFUSED)return status;
    if(!same_runtime(current,before)||!env.unchanged(*held,current.program))return OA_IPC_UNTRUSTED;
    status=selection_budget(deadline,cancellation);if(status!=OA_IPC_OK)return status;
    // Recheck absence immediately before dispatch. A concurrent normal start
    // leaves availability to the caller's ordinary verified resolver retry.
    status=env.absent(absent);if(status!=OA_IPC_OK)return status;
    status=selection_budget(deadline,cancellation);if(status!=OA_IPC_OK)return status;
    if(!absent){outcome=OA_IPC_ACTIVATION_ENDPOINT_PRESENT;return OA_IPC_OK;}
    const auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-local_stream::Clock::now()).count();
    if(left<=0)return OA_IPC_TIMEOUT;
    const std::vector<std::string> arguments{"start","--timeout",std::to_string(left)+"ms"};
    int code=-1;
    status=env.run(*held,current.program,arguments,deadline,cancellation,code);
    if(status!=OA_IPC_OK)return status;
    status=selection_budget(deadline,cancellation);if(status!=OA_IPC_OK)return status;
    RuntimeIdentity after;
    status=env.select(after,deadline,cancellation);if(status!=OA_IPC_OK)return status;
    status=env.ordinary(outcome);if(status!=OA_IPC_OK||outcome==OA_IPC_ACTIVATION_REFUSED)return status;
    if(!same_runtime(current,after)||!env.unchanged(*held,current.program))return OA_IPC_UNTRUSTED;
    status=selection_budget(deadline,cancellation);if(status!=OA_IPC_OK)return status;
    switch(code) {
    case 0:outcome=OA_IPC_ACTIVATION_REQUEST_COMPLETED;return OA_IPC_OK;
    case 3:outcome=OA_IPC_ACTIVATION_UPGRADE_IN_PROGRESS;return OA_IPC_OK;
    case 4:outcome=OA_IPC_ACTIVATION_REFUSED;return OA_IPC_OK;
    default:return OA_IPC_IO_ERROR;
    }
}

#ifdef _WIN32
struct RuntimeActivationFile {
    HANDLE value=INVALID_HANDLE_VALUE;
    std::vector<HANDLE> ancestors;
    ServerGuard::FileIdentity identity;
    std::wstring image;
    ~RuntimeActivationFile(){
        if(value!=INVALID_HANDLE_VALUE)::CloseHandle(value);
        for(auto it=ancestors.rbegin();it!=ancestors.rend();++it)::CloseHandle(*it);
    }
    static std::unique_ptr<RuntimeActivationFile> open(const std::string& name) {
        auto file=std::make_unique<RuntimeActivationFile>();
        if(!ServerGuard::wide(name,file->image)||!ServerGuard::local_image(file->image))return {};
        // Activation requires a stable ordinary local namespace through dispatch.
        // This stricter proof is specific to starting the selected executable;
        // ordinary verified connections retain their existing path semantics.
        if(file->image.find(L'/',3)!=std::wstring::npos||file->image.find(L':',2)!=std::wstring::npos)return {};
        size_t begin=3;
        for(size_t end=3;;){
            const auto directory=file->image.substr(0,end);
            HANDLE held=::CreateFileW(directory.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ,nullptr,
                OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
            if(held==INVALID_HANDLE_VALUE)return {};
            try{file->ancestors.push_back(held);}catch(...){::CloseHandle(held);throw;}
            BY_HANDLE_FILE_INFORMATION info{};
            if(!::GetFileInformationByHandle(held,&info)||!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)||
                info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)return {};
            end=file->image.find(L'\\',begin);
            const auto component=file->image.substr(begin,end==std::wstring::npos?end:end-begin);
            if(component.empty()||component==L"."||component==L"..")return {};
            if(end==std::wstring::npos)break;
            begin=end+1;
        }
        file->value=::CreateFileW(file->image.c_str(),GENERIC_READ|FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if(file->value==INVALID_HANDLE_VALUE)return {};
        BY_HANDLE_FILE_INFORMATION info{};
        FILE_ID_INFO identity{};
        if(!::GetFileInformationByHandle(file->value,&info)||
            info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_DEVICE|FILE_ATTRIBUTE_REPARSE_POINT)||
            !::GetFileInformationByHandleEx(file->value,FileIdInfo,&identity,sizeof identity))return {};
        file->identity.volume=identity.VolumeSerialNumber;file->identity.id=identity.FileId;
        return file;
    }
    bool unchanged(const std::string& name) const {
        std::wstring path;ServerGuard::FileIdentity now;
        return ServerGuard::wide(name,path)&&path==image&&ServerGuard::identity_of(path,now)&&now==identity;
    }
};
struct ActivationHandle {
    HANDLE value=nullptr;
    explicit ActivationHandle(HANDLE h=nullptr):value(h==INVALID_HANDLE_VALUE?nullptr:h){}
    ~ActivationHandle(){reset();}
    void reset(){if(value)::CloseHandle(value);value=nullptr;}
    ActivationHandle(const ActivationHandle&)=delete;
    ActivationHandle& operator=(const ActivationHandle&)=delete;
};
struct ActivationChild {
    ActivationHandle process;
    explicit ActivationChild(HANDLE handle):process(handle){}
    ~ActivationChild(){
        if(process.value&&::WaitForSingleObject(process.value,0)!=WAIT_OBJECT_0){
            ::TerminateProcess(process.value,1);
            ::WaitForSingleObject(process.value,INFINITE);
        }
    }
};
// Bounded draining cannot let a continuously writing descendant extend the
// start-command budget. Only the command's stable process handle is stopped.
inline void activation_drain(HANDLE pipe) {
    char buffer[4096];
    for(unsigned pass=0;pass<16;pass++){
        DWORD available=0,moved=0;
        if(!::PeekNamedPipe(pipe,nullptr,0,nullptr,&available,nullptr)||!available)return;
        if(!::ReadFile(pipe,buffer,std::min<DWORD>(available,sizeof buffer),&moved,nullptr)||!moved)return;
    }
}
inline oa_ipc_status run_activation_child(const RuntimeActivationFile& file,const std::vector<std::string>& arguments,
    local_stream::Deadline deadline,local_stream::Cancellation* cancellation,int& exit_code) {
    std::wstring command=L"\""+file.image+L"\"";
    for(const auto& argument:arguments){
        if(argument.empty()||argument.find_first_of(" \t\"")!=std::string::npos)return OA_IPC_INVALID_ARGUMENT;
        command+=L" "+std::wstring(argument.begin(),argument.end());
    }
    const auto separator=file.image.find_last_of(L"\\/");
    if(separator==std::wstring::npos)return OA_IPC_UNTRUSTED;
    const auto directory=file.image.substr(0,separator);
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};
    HANDLE read=nullptr,write=nullptr;
    if(!::CreatePipe(&read,&write,&attributes,0))return OA_IPC_IO_ERROR;
    ActivationHandle reader(read),writer(write);
    if(!::SetHandleInformation(reader.value,HANDLE_FLAG_INHERIT,0))return OA_IPC_IO_ERROR;
    ActivationHandle input(::CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
        &attributes,OPEN_EXISTING,0,nullptr));
    if(!input.value)return OA_IPC_IO_ERROR;
    SIZE_T bytes=0;::InitializeProcThreadAttributeList(nullptr,1,0,&bytes);
    if(!bytes)return OA_IPC_IO_ERROR;
    std::vector<unsigned char> storage(bytes);
    auto list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if(!::InitializeProcThreadAttributeList(list,1,0,&bytes))return OA_IPC_IO_ERROR;
    struct ListOwner{LPPROC_THREAD_ATTRIBUTE_LIST value;~ListOwner(){::DeleteProcThreadAttributeList(value);}} owner{list};
    HANDLE inherited[]={input.value,writer.value};
    if(!::UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof inherited,nullptr,nullptr))return OA_IPC_IO_ERROR;
    STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof startup;
    startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;startup.StartupInfo.wShowWindow=SW_HIDE;
    startup.StartupInfo.hStdInput=input.value;startup.StartupInfo.hStdOutput=writer.value;startup.StartupInfo.hStdError=writer.value;
    startup.lpAttributeList=list;
    auto status=selection_budget(deadline,cancellation);if(status!=OA_IPC_OK)return status;
    PROCESS_INFORMATION child{};
    if(!::CreateProcessW(file.image.c_str(),command.data(),nullptr,nullptr,TRUE,
        CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,directory.c_str(),&startup.StartupInfo,&child))return OA_IPC_IO_ERROR;
    ActivationChild process(child.hProcess);ActivationHandle thread(child.hThread);
    writer.reset();input.reset();
    for(;;){
        status=selection_budget(deadline,cancellation);if(status!=OA_IPC_OK)return status;
        activation_drain(reader.value);
        HANDLE waits[]={process.process.value,cancellation?cancellation->wake():nullptr};
        auto waited=::WaitForMultipleObjects(cancellation?2:1,waits,FALSE,
            static_cast<DWORD>(std::min(local_stream::detail::remaining_ms(deadline),10)));
        if(waited==WAIT_OBJECT_0)break;
        if(cancellation&&waited==WAIT_OBJECT_0+1)return OA_IPC_CANCELLED;
        if(waited!=WAIT_TIMEOUT)return OA_IPC_IO_ERROR;
    }
    activation_drain(reader.value);DWORD code=0;
    if(!::GetExitCodeProcess(process.process.value,&code))return OA_IPC_IO_ERROR;
    exit_code=static_cast<int>(code);return selection_budget(deadline,cancellation);
}
struct RuntimeActivationEnvironment {
    bool profile_checked=false;
    oa_ipc_status ordinary(int32_t& outcome) {
        if(!ipc::detail::runtime_endpoint_override().empty()){outcome=OA_IPC_ACTIVATION_REFUSED;return OA_IPC_OK;}
        HANDLE impersonation=nullptr;
        if(::OpenThreadToken(::GetCurrentThread(),TOKEN_QUERY,TRUE,&impersonation)){
            ::CloseHandle(impersonation);outcome=OA_IPC_ACTIVATION_REFUSED;return OA_IPC_OK;
        }
        if(::GetLastError()!=ERROR_NO_TOKEN)return OA_IPC_PROOF_UNAVAILABLE;
        HANDLE raw=nullptr;if(!::OpenProcessToken(::GetCurrentProcess(),TOKEN_QUERY,&raw))return OA_IPC_PROOF_UNAVAILABLE;
        ActivationHandle token(raw);TOKEN_ELEVATION elevation{};DWORD bytes=0;
        if(!::GetTokenInformation(token.value,TokenElevation,&elevation,sizeof elevation,&bytes))return OA_IPC_PROOF_UNAVAILABLE;
        if(elevation.TokenIsElevated){outcome=OA_IPC_ACTIVATION_REFUSED;return OA_IPC_OK;}
        if(!profile_checked){
            try{if(ipc::detail::current_profile_view().virtualized){outcome=OA_IPC_ACTIVATION_REFUSED;return OA_IPC_OK;}}
            catch(const std::bad_alloc&){throw;}
            catch(...){return OA_IPC_PROOF_UNAVAILABLE;}
            profile_checked=true;
        }
        return OA_IPC_OK;
    }
    oa_ipc_status select(RuntimeIdentity& value,local_stream::Deadline deadline,local_stream::Cancellation* cancel){return select_runtime_identity(value,deadline,cancel);}
    auto hold(const std::string& program){return RuntimeActivationFile::open(program);}
    bool unchanged(const RuntimeActivationFile& file,const std::string& program){return file.unchanged(program);}
    oa_ipc_status absent(bool& value){
        const auto endpoint=ipc::runtime_endpoint();const std::wstring wide(endpoint.begin(),endpoint.end());
        if(::WaitNamedPipeW(wide.c_str(),1)){value=false;return OA_IPC_OK;}
        const auto error=::GetLastError();
        if(error==ERROR_FILE_NOT_FOUND||error==ERROR_PATH_NOT_FOUND){value=true;return OA_IPC_OK;}
        if(error==ERROR_SEM_TIMEOUT||error==ERROR_PIPE_BUSY){value=false;return OA_IPC_OK;}
        return OA_IPC_PROOF_UNAVAILABLE;
    }
    oa_ipc_status run(const RuntimeActivationFile& file,const std::string&,const std::vector<std::string>& arguments,
        local_stream::Deadline deadline,local_stream::Cancellation* cancel,int& code){return run_activation_child(file,arguments,deadline,cancel,code);}
};
#elif defined(__linux__)
struct RuntimeActivationFile {
    int descriptor=-1;struct stat identity{};
    ~RuntimeActivationFile(){if(descriptor>=0)::close(descriptor);}
    static std::unique_ptr<RuntimeActivationFile> open(const std::string& name){
        auto file=std::make_unique<RuntimeActivationFile>();
        file->descriptor=::open(name.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        unsigned char magic[4]{};
        if(file->descriptor<0||::fstat(file->descriptor,&file->identity)||!S_ISREG(file->identity.st_mode)||
            !(file->identity.st_mode&0111)||(file->identity.st_mode&(S_ISUID|S_ISGID))||
            ::pread(file->descriptor,magic,4,0)!=4||std::memcmp(magic,"\x7f" "ELF",4))return {};
        return file;
    }
    bool unchanged(const std::string& name) const {
        struct stat current{};
        return !::lstat(name.c_str(),&current)&&S_ISREG(current.st_mode)&&current.st_dev==identity.st_dev&&current.st_ino==identity.st_ino;
    }
};
struct RuntimeActivationEnvironment {
    oa_ipc_status ordinary(int32_t& outcome){
        if(::getuid()==0||::getuid()!=ipc::process_effective_uid()||!ipc::detail::runtime_endpoint_override().empty()){outcome=OA_IPC_ACTIVATION_REFUSED;return OA_IPC_OK;}
        return OA_IPC_OK;
    }
    oa_ipc_status select(RuntimeIdentity& value,local_stream::Deadline deadline,local_stream::Cancellation* cancel){return select_runtime_identity(value,deadline,cancel);}
    auto hold(const std::string& program){return RuntimeActivationFile::open(program);}
    bool unchanged(const RuntimeActivationFile& file,const std::string& program){return file.unchanged(program);}
    oa_ipc_status absent(bool& value){
        struct stat info{};const auto endpoint=ipc::runtime_endpoint();
        if(!::lstat(endpoint.c_str(),&info)){value=false;return OA_IPC_OK;}
        if(errno==ENOENT||errno==ENOTDIR){value=true;return OA_IPC_OK;}
        return OA_IPC_PROOF_UNAVAILABLE;
    }
    oa_ipc_status run(const RuntimeActivationFile& file,const std::string& program,const std::vector<std::string>& arguments,
        local_stream::Deadline deadline,local_stream::Cancellation* cancel,int& code){
        std::string ignored;return linux_selection::run_owned(ignored,code,deadline,cancel,program.c_str(),arguments,file.descriptor,false,true);
    }
};
#endif

inline oa_ipc_status activate_runtime(const RuntimeIdentity& expected,local_stream::Deadline deadline,
    local_stream::Cancellation* cancel,int32_t& outcome){
    outcome=OA_IPC_ACTIVATION_NONE;
#if defined(_WIN32)||defined(__linux__)
    RuntimeActivationEnvironment environment;
    return activate_runtime_with(expected,deadline,cancel,outcome,environment);
#else
    (void)expected;auto state=selection_budget(deadline,cancel);
    return state==OA_IPC_OK?OA_IPC_PROOF_UNAVAILABLE:state;
#endif
}
}
