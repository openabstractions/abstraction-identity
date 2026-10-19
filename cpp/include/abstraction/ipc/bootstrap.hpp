#pragma once
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>
#include <abstraction/ipc/process.hpp>
#ifndef _WIN32
#include <cerrno>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace abstraction::ipc {
namespace detail {
// Fixed native bootstrap input. Windows DLLs may have independent CRT copies;
// read the process environment directly and return owned UTF-8 bytes.
inline std::string runtime_endpoint_override() {
#ifdef _WIN32
 std::vector<wchar_t> value(32768);
 ::SetLastError(ERROR_SUCCESS);
 const auto count=::GetEnvironmentVariableW(L"ABSTRACTION_RUNTIME_ENDPOINT",value.data(),static_cast<DWORD>(value.size()));
 if(!count){
  const auto error=::GetLastError();
  if(error==ERROR_SUCCESS||error==ERROR_ENVVAR_NOT_FOUND)return {};
  throw std::system_error(static_cast<int>(error),std::system_category(),"bootstrap environment");
 }
 if(count>=value.size())throw std::system_error(ERROR_BUFFER_OVERFLOW,std::system_category(),"bootstrap environment");
 const auto bytes=::WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(count),nullptr,0,nullptr,nullptr);
 if(!bytes)throw std::system_error(static_cast<int>(::GetLastError()),std::system_category(),"bootstrap environment UTF-8");
 std::string result(static_cast<size_t>(bytes),'\0');
 if(::WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(count),result.data(),bytes,nullptr,nullptr)!=bytes)
  throw std::system_error(static_cast<int>(::GetLastError()),std::system_category(),"bootstrap environment UTF-8");
 return result;
#else
 const char* value=std::getenv("ABSTRACTION_RUNTIME_ENDPOINT");return value?value:"";
#endif
}
}
// Native address primitive; facade owns logical service selection/validation.
#ifndef _WIN32
inline void private_directory(const std::filesystem::path& path,bool missing_allowed) {
 struct stat info{};
 if(::lstat(path.c_str(),&info)!=0){if(missing_allowed&&errno==ENOENT)return;throw std::runtime_error("bootstrap: namespace cannot be inspected");}
 if(!S_ISDIR(info.st_mode)||info.st_uid!=process_effective_uid()||(info.st_mode&0777)!=0700)throw std::runtime_error("bootstrap: namespace is not an owned ordinary0700 directory");
}
#endif
// Pure naming: a missing namespace is never created by a client.
inline std::string account_endpoint(const std::string& service) {
#ifdef _WIN32
 return std::string(R"(\\.\pipe\openabstractions-user-)")+process_user_sid()+"-"+service;
#else
 if(::getuid()!=process_effective_uid())throw std::runtime_error("bootstrap: mixed real/effective user identity");
 std::filesystem::path directory;
 if(const char* xdg=std::getenv("XDG_RUNTIME_DIR");xdg&&*xdg){
  std::filesystem::path base(xdg);if(!base.is_absolute())throw std::runtime_error("bootstrap: relative XDG_RUNTIME_DIR");
  private_directory(base,false);directory=base/"openabstractions";
 }else{
  const char* temporary=std::getenv("TMPDIR");std::filesystem::path base(temporary&&*temporary?temporary:"/tmp");
  if(!base.is_absolute())throw std::runtime_error("bootstrap: relative temporary directory");
  directory=base/("openabstractions-"+std::to_string(process_effective_uid()));
 }
 directory=directory.lexically_normal();private_directory(directory,true);
 return (directory/(service+".sock")).string();
#endif
}
// Shared native runtime convention; explicit override and installed Mac XPC stay unchanged.
inline std::string runtime_endpoint() {
#ifdef __APPLE__
 return "xpc:com.openabstractions.runtime-v1";
#else
 auto value=detail::runtime_endpoint_override();if(!value.empty())return value;
 return account_endpoint("runtime-v1");
#endif
}
}
