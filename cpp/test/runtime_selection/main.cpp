#ifdef ABSTRACTION_IPC_TEST_LEGACY_LINUX_UAPI
#include "legacy_linux_uapi.h"
#endif
#include <abstraction/ipc/client.h>
#include <abstraction/ipc/bootstrap.hpp>
#include "../../src/runtime_selection.h"
#include "../../src/runtime_activation.h"
#include <iostream>
#include <stdexcept>
#include <thread>

void require(bool condition,const char* message) { if(!condition)throw std::runtime_error(message); }
#include "linux.h"
#include "darwin.h"

#ifdef _WIN32
#include <winioctl.h>
struct ActivationChildIdentity {DWORD pid;FILETIME birth;};
static void activation_junction(const std::wstring& path,const std::wstring& target){
    require(::CreateDirectoryW(path.c_str(),nullptr)!=0,"own junction directory");
    HANDLE directory=::CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(directory!=INVALID_HANDLE_VALUE,"open own junction");
    const auto substitute=L"\\??\\"+target;
    const auto subbytes=substitute.size()*sizeof(wchar_t),printbytes=target.size()*sizeof(wchar_t);
    std::vector<unsigned char> data(16+subbytes+sizeof(wchar_t)+printbytes+sizeof(wchar_t));
    const DWORD tag=IO_REPARSE_TAG_MOUNT_POINT;
    const WORD fields[]={static_cast<WORD>(data.size()-8),0,0,static_cast<WORD>(subbytes),
        static_cast<WORD>(subbytes+sizeof(wchar_t)),static_cast<WORD>(printbytes)};
    std::memcpy(data.data(),&tag,sizeof tag);std::memcpy(data.data()+4,fields,sizeof fields);
    std::memcpy(data.data()+16,substitute.data(),subbytes);
    std::memcpy(data.data()+16+subbytes+sizeof(wchar_t),target.data(),printbytes);
    DWORD moved=0;const bool set=::DeviceIoControl(directory,FSCTL_SET_REPARSE_POINT,data.data(),
        static_cast<DWORD>(data.size()),nullptr,0,&moved,nullptr)!=0;
    ::CloseHandle(directory);require(set,"set own junction");
}
static std::wstring activation_environment(const wchar_t* name){
    std::vector<wchar_t> value(32768);auto size=::GetEnvironmentVariableW(name,value.data(),static_cast<DWORD>(value.size()));
    return size&&size<value.size()?std::wstring(value.data(),size):std::wstring();
}
static int activation_child_fixture(int argc,char** argv){
    if(argc!=4||std::string(argv[2])!="--timeout")return 21;
    const auto path=activation_environment(L"OA_ACTIVATION_TEST_PIDFILE");
    if(path.empty())return 22;
    ActivationChildIdentity identity{::GetCurrentProcessId(),{}};FILETIME exit{},kernel{},user{};
    if(!::GetProcessTimes(::GetCurrentProcess(),&identity.birth,&exit,&kernel,&user))return 23;
    HANDLE file=::CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)return 24;DWORD moved=0;
    const bool saved=::WriteFile(file,&identity,sizeof identity,&moved,nullptr)&&moved==sizeof identity;
    ::CloseHandle(file);if(!saved)return 25;
    const auto mode=activation_environment(L"OA_ACTIVATION_TEST_MODE");
    if(mode==L"stall")::Sleep(INFINITE);
    if(mode==L"flood"){
        char output[4096]{};
        for(;;)if(!::WriteFile(::GetStdHandle(STD_OUTPUT_HANDLE),output,sizeof output,&moved,nullptr))return 26;
    }
    return mode==L"upgrade"?3:mode==L"refused"?4:0;
}
static void windows_activation_children(){
    using namespace abstraction;
    using namespace ipc_internal;
    std::vector<wchar_t> image(32768);
    auto length=::GetModuleFileNameW(nullptr,image.data(),static_cast<DWORD>(image.size()));
    require(length&&length<image.size(),"own fixture image");
    std::wstring own(image.data(),length);
    const auto root=own.substr(0,own.find_last_of(L"\\/"))+L"\\activation-owned-"+std::to_wstring(::GetCurrentProcessId());
    require(::CreateDirectoryW(root.c_str(),nullptr)!=0,"fresh owned activation fixture");
    const auto child=root+L"\\openabstractions.exe",pidfile=root+L"\\child.bin";
    require(::CopyFileW(own.c_str(),child.c_str(),TRUE)!=0,"copy own activation fixture");
    auto narrow=[](const std::wstring& value){
        auto size=::WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr);
        require(size>0,"fixture UTF8");std::string result(static_cast<size_t>(size),'\0');
        ::WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),result.data(),size,nullptr,nullptr);return result;
    };
    auto held=RuntimeActivationFile::open(narrow(child));require(bool(held),"hold own executable identity");
    FILE_ID_INFO actual{};
    require(::GetFileInformationByHandleEx(held->value,FileIdInfo,&actual,sizeof actual)&&
        held->identity.volume==actual.VolumeSerialNumber&&
        !std::memcmp(held->identity.id.Identifier,actual.FileId.Identifier,sizeof actual.FileId.Identifier),
        "activation identity comes from held executable handle");
    require(!::MoveFileExW(child.c_str(),(child+L".replacement").c_str(),0),"held image denies namespace replacement");
    require(!::MoveFileExW(root.c_str(),(root+L"-moved").c_str(),0),"held ancestor denies rename through launch");
    require(held->unchanged(narrow(child)),"held executable remains same file");
    const auto alias=root+L"\\alias";
    activation_junction(alias,root);
    require(!RuntimeActivationFile::open(narrow(alias+L"\\openabstractions.exe")),"activation refuses reparse ancestor");
    // The rejected attempt must release its root-to-leaf handles. This exact
    // owned junction can be deleted without touching its target or payload.
    require(::RemoveDirectoryW(alias.c_str())!=0,"rejected reparse proof releases handles");
    require(!RuntimeActivationFile::open(narrow(root+L"\\missing.exe")),"missing executable refuses proof");
    const auto old_local=activation_environment(L"LOCALAPPDATA");
    ::SetEnvironmentVariableW(L"LOCALAPPDATA",L"Z:\\foreign-environment-override");
    unsigned creates=0;bool profile_refused=false,right_root=false;
    try{ipc::detail::profile_view_with([&]{return root;},[&](const std::wstring& path){
        creates++;right_root=path.compare(0,root.size()+1,root+L"\\")==0;return false;});
    }catch(const std::runtime_error&){profile_refused=true;}
    require(profile_refused&&creates==1&&right_root,"known-folder source selected independently of environment");
    creates=0;profile_refused=false;
    try{ipc::detail::profile_view_with([]()->std::wstring{throw std::runtime_error("known-folder unavailable");},
        [&](const std::wstring&){creates++;return true;});}
    catch(const std::runtime_error&){profile_refused=true;}
    require(profile_refused&&creates==0,"unknown proof reached file creation");
    ::SetEnvironmentVariableW(L"LOCALAPPDATA",old_local.empty()?nullptr:old_local.c_str());
    const auto old_mode=activation_environment(L"OA_ACTIVATION_TEST_MODE"),old_file=activation_environment(L"OA_ACTIVATION_TEST_PIDFILE");
    ::SetEnvironmentVariableW(L"OA_ACTIVATION_TEST_PIDFILE",pidfile.c_str());
    for(const auto* mode:{L"ok",L"upgrade",L"refused",L"stall",L"flood",L"cancel"}){
        ::SetEnvironmentVariableW(L"OA_ACTIVATION_TEST_MODE",!wcscmp(mode,L"cancel")?L"stall":mode);
        local_stream::Cancellation cancellation;std::thread signal;
        if(!wcscmp(mode,L"cancel"))signal=std::thread([&]{
            for(unsigned pass=0;pass<150;pass++){
                WIN32_FILE_ATTRIBUTE_DATA info{};
                if(::GetFileAttributesExW(pidfile.c_str(),GetFileExInfoStandard,&info)&&!info.nFileSizeHigh&&info.nFileSizeLow==sizeof(ActivationChildIdentity))break;
                ::Sleep(10);
            }
            cancellation.signal();
        });
        const bool bounded=!wcscmp(mode,L"stall")||!wcscmp(mode,L"flood");
        auto start=local_stream::Clock::now();int code=-1;
        auto result=run_activation_child(*held,{"start","--timeout","500ms"},start+std::chrono::milliseconds(bounded?500:2000),
            !wcscmp(mode,L"cancel")?&cancellation:nullptr,code);
        if(signal.joinable())signal.join();
        require(local_stream::Clock::now()-start<std::chrono::seconds(3),"owned child did not extend budget");
        if(bounded)require(result==OA_IPC_TIMEOUT,"stall/flood bounded deadline");
        else if(!wcscmp(mode,L"cancel"))require(result==OA_IPC_CANCELLED,"owned child cancellation");
        else require(result==OA_IPC_OK&&code==(!wcscmp(mode,L"upgrade")?3:!wcscmp(mode,L"refused")?4:0),"owned child exit status");
        HANDLE file=::CreateFileW(pidfile.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        require(file!=INVALID_HANDLE_VALUE,"child identity receipt");ActivationChildIdentity identity{};DWORD moved=0;
        const bool read=::ReadFile(file,&identity,sizeof identity,&moved,nullptr)&&moved==sizeof identity;::CloseHandle(file);require(read,"child receipt bytes");
        HANDLE process=::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,identity.pid);
        if(process){FILETIME birth{},exit{},kernel{},user{};
            require(::GetProcessTimes(process,&birth,&exit,&kernel,&user)!=0,"observed child creation");
            require(::CompareFileTime(&birth,&identity.birth)!=0||::WaitForSingleObject(process,0)==WAIT_OBJECT_0,"original owned child survived");
            ::CloseHandle(process);
        }else require(::GetLastError()==ERROR_INVALID_PARAMETER,"child observation unavailable");
        require(::DeleteFileW(pidfile.c_str())!=0,"own child receipt cleanup");
    }
    ::SetEnvironmentVariableW(L"OA_ACTIVATION_TEST_MODE",old_mode.empty()?nullptr:old_mode.c_str());
    ::SetEnvironmentVariableW(L"OA_ACTIVATION_TEST_PIDFILE",old_file.empty()?nullptr:old_file.c_str());
    held.reset();
    require(::MoveFileExW(root.c_str(),(root+L"-moved").c_str(),0)&&
        ::MoveFileExW((root+L"-moved").c_str(),root.c_str(),0),"successful and failed proof paths release ancestor handles");
    require(::DeleteFileW(child.c_str())&&::RemoveDirectoryW(root.c_str()),"owned fixture exact cleanup");
}
#endif

// The native recipe receives inert platform operations here. No registration,
// installed runtime, endpoint, or child process is consulted by these cases.
struct ActivationFixture {
    struct Held {};
    abstraction::ipc_internal::RuntimeIdentity identity{OA_IPC_PRINCIPAL_POSIX_UID,"1001","/owned/openabstractions"};
    oa_ipc_status ordinary_status=OA_IPC_OK,select_status=OA_IPC_OK,run_status=OA_IPC_OK;
    int selections=0,probes=0,runs=0,code=0,change_at=0;
    bool present=false,stable=true,holdable=true,ordinary_refused=false;
    abstraction::local_stream::Cancellation* cancel_on_probe=nullptr;
    oa_ipc_status ordinary(int32_t& outcome){if(ordinary_refused)outcome=OA_IPC_ACTIVATION_REFUSED;return ordinary_status;}
    oa_ipc_status select(abstraction::ipc_internal::RuntimeIdentity& value,
        abstraction::local_stream::Deadline,abstraction::local_stream::Cancellation*) {
        ++selections;value=identity;
        if(change_at==selections)value.program+="-replacement";
        return select_status;
    }
    std::unique_ptr<Held> hold(const std::string&){return holdable?std::make_unique<Held>():nullptr;}
    bool unchanged(const Held&,const std::string&){return stable;}
    oa_ipc_status absent(bool& value){++probes;value=!present;if(cancel_on_probe)cancel_on_probe->signal();return OA_IPC_OK;}
    oa_ipc_status run(const Held&,const std::string& program,const std::vector<std::string>& args,
        abstraction::local_stream::Deadline,abstraction::local_stream::Cancellation*,int& result) {
        ++runs;require(program==identity.program,"activation executable changed");
        require(args.size()==3&&args[0]=="start"&&args[1]=="--timeout"&&args[2].size()>2&&
            args[2].substr(args[2].size()-2)=="ms","activation fixed arguments");
        result=code;return run_status;
    }
};
void activation_recipe_tests() {
    using namespace abstraction;
    using namespace ipc_internal;
    auto deadline=[](){return local_stream::Clock::now()+std::chrono::seconds(1);};
    for(auto code:{0,3,4,7}) {
        ActivationFixture env;env.code=code;int32_t outcome=99;
        auto status=activate_runtime_with(env.identity,deadline(),nullptr,outcome,env);
        require(status==(code==7?OA_IPC_IO_ERROR:OA_IPC_OK),"activation exit status");
        require(outcome==(code==0?OA_IPC_ACTIVATION_REQUEST_COMPLETED:code==3?OA_IPC_ACTIVATION_UPGRADE_IN_PROGRESS:
            code==4?OA_IPC_ACTIVATION_REFUSED:OA_IPC_ACTIVATION_NONE),"activation outcome");
        require(env.runs==1&&env.selections==3&&env.probes==2,"activation finite recipe");
    }
    ActivationFixture present;present.present=true;int32_t outcome=99;
    require(activate_runtime_with(present.identity,deadline(),nullptr,outcome,present)==OA_IPC_OK&&
        outcome==OA_IPC_ACTIVATION_ENDPOINT_PRESENT&&present.runs==0,"present endpoint never starts");
    for(int change:{1,2,3}) {
        ActivationFixture env;env.change_at=change;outcome=99;
        require(activate_runtime_with(env.identity,deadline(),nullptr,outcome,env)==OA_IPC_UNTRUSTED&&
            outcome==OA_IPC_ACTIVATION_NONE&&env.runs==(change==3?1:0),"selection replacement refused");
    }
    ActivationFixture unstable;unstable.stable=false;outcome=99;
    require(activate_runtime_with(unstable.identity,deadline(),nullptr,outcome,unstable)==OA_IPC_UNTRUSTED&&
        unstable.runs==0&&outcome==OA_IPC_ACTIVATION_NONE,"held identity replacement refused");
    ActivationFixture cancelled;local_stream::Cancellation cancellation;cancelled.cancel_on_probe=&cancellation;outcome=99;
    require(activate_runtime_with(cancelled.identity,deadline(),&cancellation,outcome,cancelled)==OA_IPC_CANCELLED&&
        cancelled.runs==0&&outcome==OA_IPC_ACTIVATION_NONE,"cancellation during absence never starts");
    ActivationFixture expired;outcome=99;
    require(activate_runtime_with(expired.identity,local_stream::Clock::now(),nullptr,outcome,expired)==OA_IPC_TIMEOUT&&
        expired.selections==0&&expired.runs==0&&outcome==OA_IPC_ACTIVATION_NONE,"expired activation has no platform effects");
    ActivationFixture refused;refused.ordinary_refused=true;outcome=99;
    require(activate_runtime_with(refused.identity,deadline(),nullptr,outcome,refused)==OA_IPC_OK&&
        outcome==OA_IPC_ACTIVATION_REFUSED&&refused.selections==0&&refused.runs==0,"ordinary-account refusal has no dispatch");
    ActivationFixture unknown;unknown.ordinary_status=OA_IPC_PROOF_UNAVAILABLE;outcome=99;
    require(activate_runtime_with(unknown.identity,deadline(),nullptr,outcome,unknown)==OA_IPC_PROOF_UNAVAILABLE&&
        outcome==OA_IPC_ACTIVATION_NONE&&unknown.selections==0&&unknown.runs==0,"unknown profile facility refuses proof");
}

int main(int argc,char** argv) { try {
#ifdef _WIN32
    if(argc>1&&std::string(argv[1])=="start")return activation_child_fixture(argc,argv);
#endif
#ifdef __linux__
    if(argc>1)return linux_helper(argc,argv);
#else
    (void)argc;(void)argv;
#endif
    activation_recipe_tests();
    oa_ipc_runtime_selection* selected=reinterpret_cast<oa_ipc_runtime_selection*>(1);
    require(oa_ipc_select_runtime(0,nullptr,&selected)==OA_IPC_TIMEOUT && selected==nullptr,"expired selection");
    require(oa_ipc_selected_server(nullptr)==nullptr,"null expectation");
    oa_ipc_runtime_selection_release(nullptr);
    int32_t activation_outcome=99;
    require(oa_ipc_activate_runtime(nullptr,1000,nullptr,&activation_outcome)==OA_IPC_INVALID_ARGUMENT&&
        activation_outcome==OA_IPC_ACTIVATION_NONE,"null activation expectation has no effects");
    const std::string activation_principal="1001";
#ifdef _WIN32
    windows_activation_children();
    {
        const auto original=activation_environment(L"ABSTRACTION_RUNTIME_ENDPOINT");
        require(::SetEnvironmentVariableW(L"ABSTRACTION_RUNTIME_ENDPOINT",L"owned-process-only-override")!=0,"own process override");
        abstraction::ipc_internal::RuntimeActivationEnvironment environment;
        environment.profile_checked=true; // No profile probe or installed selection in this control.
        int32_t outcome=OA_IPC_ACTIVATION_NONE;
        require(environment.ordinary(outcome)==OA_IPC_OK&&outcome==OA_IPC_ACTIVATION_REFUSED,"OS-only override fences native activation");
        require(::SetEnvironmentVariableW(L"ABSTRACTION_RUNTIME_ENDPOINT",original.empty()?nullptr:original.c_str())!=0,"restore own process override");
    }
    const std::string activation_program="C:\\owned\\openabstractions.exe";
    const auto activation_kind=OA_IPC_PRINCIPAL_WINDOWS_SID;
#else
    const std::string activation_program="/owned/openabstractions";
    const auto activation_kind=OA_IPC_PRINCIPAL_POSIX_UID;
#endif
    oa_ipc_server_expectation activation_expected{sizeof(oa_ipc_server_expectation),1,activation_kind,0,
        activation_principal.data(),activation_principal.size(),activation_program.data(),activation_program.size()};
    require(oa_ipc_activate_runtime(&activation_expected,0,nullptr,&activation_outcome)==OA_IPC_TIMEOUT&&
        activation_outcome==OA_IPC_ACTIVATION_NONE,"expired native activation has no platform effects");
    require(oa_ipc_activate_runtime(&activation_expected,1000,nullptr,nullptr)==OA_IPC_INVALID_ARGUMENT,"activation requires outcome storage");
    for(auto field:{0,1,2}){
        auto invalid=activation_expected;
        if(field==0)invalid.struct_size--;else if(field==1)invalid.version++;else invalid.reserved=1;
        activation_outcome=99;
        require(oa_ipc_activate_runtime(&invalid,1000,nullptr,&activation_outcome)==OA_IPC_INVALID_ARGUMENT&&
            activation_outcome==OA_IPC_ACTIVATION_NONE,"activation input layout validation");
    }
    oa_ipc_cancellation* cancellation=nullptr;
    require(oa_ipc_cancellation_create(&cancellation)==OA_IPC_OK,"cancellation allocation");
    oa_ipc_cancellation_signal(cancellation);
    require(oa_ipc_select_runtime(1000,cancellation,&selected)==OA_IPC_CANCELLED && selected==nullptr,"pre-cancelled selection");
    require(oa_ipc_activate_runtime(&activation_expected,1000,cancellation,&activation_outcome)==OA_IPC_CANCELLED&&
        activation_outcome==OA_IPC_ACTIVATION_NONE,"pre-cancelled native activation has no platform effects");
    oa_ipc_cancellation_release(cancellation);
#ifdef _WIN32
    using namespace abstraction;
    using namespace ipc_internal;
    const auto deadline=local_stream::Clock::now()+std::chrono::seconds(2);
    auto related=[](DWORD index,std::wstring& product) -> UINT {
        if(index)return ERROR_NO_MORE_ITEMS;
        product=L"{00000000-0000-0000-0000-000000000001}";return ERROR_SUCCESS;
    };
    auto property=[](const std::wstring&,MSIINSTALLCONTEXT scope,const wchar_t* key,std::wstring& value) -> UINT {
        if(scope!=MSIINSTALLCONTEXT_USERUNMANAGED)return ERROR_UNKNOWN_PRODUCT;
        value=std::wstring(key)==L"State"?L"5":L"C:\\Users\\space name\\OA";
        return ERROR_SUCCESS;
    };
    RuntimeIdentity identity;
    require(select_windows_runtime(identity,"S-1-5-21-1",deadline,nullptr,related,property)==OA_IPC_OK,"registered selection");
    require(identity.program=="C:\\Users\\space name\\OA\\tools\\openabstractions.exe" && identity.principal=="S-1-5-21-1","selected snapshot");
    auto absent=[](DWORD,std::wstring&) -> UINT {return ERROR_NO_MORE_ITEMS;};
    require(select_windows_runtime(identity,"S-1-5-21-1",deadline,nullptr,absent,property)==OA_IPC_UNTRUSTED,"missing registration");
    auto multiple=[&](const std::wstring& p,MSIINSTALLCONTEXT,const wchar_t* key,std::wstring& value) -> UINT {return property(p,MSIINSTALLCONTEXT_USERUNMANAGED,key,value);};
    require(select_windows_runtime(identity,"S-1-5-21-1",deadline,nullptr,related,multiple)==OA_IPC_UNTRUSTED,"ambiguous scope");
    auto relative=[&](const std::wstring& p,MSIINSTALLCONTEXT scope,const wchar_t* key,std::wstring& value) -> UINT {
        auto status=property(p,scope,key,value);
        if(std::wstring(key)==L"InstallLocation")value=L"relative";
        return status;
    };
    require(select_windows_runtime(identity,"S-1-5-21-1",deadline,nullptr,related,relative)==OA_IPC_UNTRUSTED,"relative path");
    auto advertised=[&](const std::wstring& p,MSIINSTALLCONTEXT scope,const wchar_t* key,std::wstring& value) -> UINT {
        auto status=property(p,scope,key,value);
        if(std::wstring(key)==L"State")value=L"1";
        return status;
    };
    require(select_windows_runtime(identity,"S-1-5-21-1",deadline,nullptr,related,advertised)==OA_IPC_UNTRUSTED,"advertised product");
#elif defined(__linux__)
    linux_tests();
#elif defined(__APPLE__)
    darwin_tests();
    ::setenv("ABSTRACTION_RUNTIME_ENDPOINT", "xpc:untrusted-environment", 1);
    require(abstraction::ipc::runtime_endpoint()=="xpc:com.openabstractions.runtime-v1","fixed Darwin endpoint");
#else
    require(oa_ipc_select_runtime(1000,nullptr,&selected)==OA_IPC_PROOF_UNAVAILABLE && selected==nullptr,"unsupported selection");
#endif
    std::cout<<"PASS runtime selection controls\n";
    return 0;
} catch(const std::exception& error) { std::cerr<<error.what()<<'\n';return 1; } }
