#pragma once
#include <abstraction/ipc/client.h>
#include "local_stream.h"
#include <set>
#include <stdexcept>
#include <vector>
#include "runtime_selection_linux.h"
#ifdef _WIN32
#include <msi.h>
#include <abstraction/ipc/process.hpp>
#endif

namespace abstraction::ipc_internal {
struct RuntimeIdentity {
    uint32_t kind=0;
    std::string principal, program;
};

inline oa_ipc_status selection_budget(local_stream::Deadline deadline, local_stream::Cancellation* cancellation) {
    if(cancellation && cancellation->requested()) return OA_IPC_CANCELLED;
    if(local_stream::Clock::now()>=deadline) return OA_IPC_TIMEOUT;
    return OA_IPC_OK;
}

#ifdef _WIN32
inline std::string selection_utf8(const std::wstring& value) {
    int n=::WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr);
    if(n<=0) throw std::runtime_error("invalid installation path");
    std::string out(n,'\0');
    if(::WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),out.data(),n,nullptr,nullptr)!=n)
        throw std::runtime_error("invalid installation path");
    return out;
}

// Parameterized OS reads let tests exercise absence/conflict/path validation
// without installing a product or writing an owner's registry.
template<class Related, class Property>
oa_ipc_status select_windows_runtime(RuntimeIdentity& out, const std::string& sid,
    local_stream::Deadline deadline, local_stream::Cancellation* cancellation,
    Related related, Property property) {
    std::wstring location;
    std::set<std::wstring> seen;
    unsigned installed=0;
    for(DWORD index=0;;++index) {
        auto budget=selection_budget(deadline,cancellation); if(budget!=OA_IPC_OK)return budget;
        if(index>=64)return OA_IPC_UNTRUSTED;
        std::wstring product;
        auto result=related(index,product);
        if(result==ERROR_NO_MORE_ITEMS)break;
        if(result!=ERROR_SUCCESS||product.empty()||!seen.insert(product).second)return OA_IPC_UNTRUSTED;
        for(auto scope:{MSIINSTALLCONTEXT_USERMANAGED,MSIINSTALLCONTEXT_USERUNMANAGED,MSIINSTALLCONTEXT_MACHINE}) {
            budget=selection_budget(deadline,cancellation);if(budget!=OA_IPC_OK)return budget;
            std::wstring state;
            result=property(product,scope,L"State",state);
            if(result==ERROR_UNKNOWN_PRODUCT)continue;
            if(result!=ERROR_SUCCESS)return OA_IPC_UNTRUSTED;
            if(state==L"1")continue;
            if(state!=L"5"||++installed>1)return OA_IPC_UNTRUSTED;
            result=property(product,scope,L"InstallLocation",location);
            if(result!=ERROR_SUCCESS||location.size()<3||location[1]!=L':'||
                (location[2]!=L'\\'&&location[2]!=L'/')||location.find(L'\0')!=std::wstring::npos)return OA_IPC_UNTRUSTED;
        }
    }
    auto budget=selection_budget(deadline,cancellation);if(budget!=OA_IPC_OK)return budget;
    if(installed!=1)return OA_IPC_UNTRUSTED;
    std::vector<wchar_t> normalized(32768);
    const auto requested=location+L"\\tools\\openabstractions.exe";
    auto n=::GetFullPathNameW(requested.c_str(),static_cast<DWORD>(normalized.size()),normalized.data(),nullptr);
    if(!n||n>=normalized.size())return OA_IPC_UNTRUSTED;
    out.kind=OA_IPC_PRINCIPAL_WINDOWS_SID;
    out.principal=sid;
    out.program=selection_utf8(std::wstring(normalized.data(),n));
    return selection_budget(deadline,cancellation);
}
#endif

#ifdef __linux__
inline oa_ipc_status select_linux_runtime(RuntimeIdentity& out,local_stream::Deadline deadline,
    local_stream::Cancellation* cancellation,const char* executable="/usr/bin/systemctl") {
    if(::getuid()!=::geteuid())return OA_IPC_UNTRUSTED;
    std::string output,program;
    auto status=linux_selection::query(output,deadline,cancellation,executable);
    if(status!=OA_IPC_OK)return status;
    if(!linux_selection::program(output,program))return OA_IPC_UNTRUSTED;
    char* resolved=::realpath(program.c_str(),nullptr);
    if(!resolved)return OA_IPC_UNTRUSTED;
    std::string canonical(resolved);::free(resolved);
    status=selection_budget(deadline,cancellation);if(status!=OA_IPC_OK)return status;
    out.kind=OA_IPC_PRINCIPAL_POSIX_UID;
    out.principal=std::to_string(::geteuid());out.program=std::move(canonical);
    return OA_IPC_OK;
}
#endif

inline oa_ipc_status select_runtime_identity(RuntimeIdentity& out, local_stream::Deadline deadline,
    local_stream::Cancellation* cancellation) {
    auto budget=selection_budget(deadline,cancellation);if(budget!=OA_IPC_OK)return budget;
#ifdef _WIN32
    HANDLE token=nullptr;
    if(::OpenThreadToken(::GetCurrentThread(),TOKEN_QUERY,TRUE,&token)) {
        ::CloseHandle(token);return OA_IPC_UNTRUSTED;
    }
    if(::GetLastError()!=ERROR_NO_TOKEN)return OA_IPC_UNTRUSTED;
    const auto sid=ipc::process_user_sid();
    auto related=[](DWORD index,std::wstring& product) {
        wchar_t value[39]{};
        UINT status=::MsiEnumRelatedProductsW(L"{CEEF6550-5E44-4E83-8E18-A855C9D941CA}",0,index,value);
        if(status==ERROR_SUCCESS)product=value;
        return status;
    };
    auto property=[](const std::wstring& product,MSIINSTALLCONTEXT scope,const wchar_t* key,std::wstring& out) {
        std::vector<wchar_t> value(32768);DWORD n=static_cast<DWORD>(value.size());
        UINT status=::MsiGetProductInfoExW(product.c_str(),nullptr,scope,key,value.data(),&n);
        if(status==ERROR_SUCCESS) {
            if(n>=value.size())return UINT(ERROR_MORE_DATA);
            out.assign(value.data(),n);
        }
        return status;
    };
    return select_windows_runtime(out,sid,deadline,cancellation,related,property);
#elif defined(__linux__)
    return select_linux_runtime(out,deadline,cancellation);
#else
    (void)out;
    return OA_IPC_PROOF_UNAVAILABLE;
#endif
}
}
