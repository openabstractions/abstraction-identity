#include <abstraction/ipc/client.h>
#include "../../src/runtime_selection.h"
#include <iostream>
#include <stdexcept>

void require(bool condition,const char* message) { if(!condition)throw std::runtime_error(message); }
#include "linux.h"

int main(int argc,char** argv) { try {
#ifdef __linux__
    if(argc>1)return linux_helper(argc,argv);
#else
    (void)argc;(void)argv;
#endif
    oa_ipc_runtime_selection* selected=reinterpret_cast<oa_ipc_runtime_selection*>(1);
    require(oa_ipc_select_runtime(0,nullptr,&selected)==OA_IPC_TIMEOUT && selected==nullptr,"expired selection");
    require(oa_ipc_selected_server(nullptr)==nullptr,"null expectation");
    oa_ipc_runtime_selection_release(nullptr);
    oa_ipc_cancellation* cancellation=nullptr;
    require(oa_ipc_cancellation_create(&cancellation)==OA_IPC_OK,"cancellation allocation");
    oa_ipc_cancellation_signal(cancellation);
    require(oa_ipc_select_runtime(1000,cancellation,&selected)==OA_IPC_CANCELLED && selected==nullptr,"pre-cancelled selection");
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
    // Read-only absent-GUID call proves the installed MSI ABI signature.
    wchar_t product[39]{};
    require(::MsiEnumRelatedProductsW(L"{00000000-0000-0000-0000-000000000001}",0,0,product)==ERROR_NO_MORE_ITEMS,"MSI read-only probe");
#elif defined(__linux__)
    linux_tests();
#else
    require(oa_ipc_select_runtime(1000,nullptr,&selected)==OA_IPC_PROOF_UNAVAILABLE && selected==nullptr,"unsupported selection");
#endif
    std::cout<<"PASS runtime selection controls\n";
    return 0;
} catch(const std::exception& error) { std::cerr<<error.what()<<'\n';return 1; } }
