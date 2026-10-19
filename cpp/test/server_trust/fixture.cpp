#include <abstraction/ipc/client.h>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
static HANDLE listener;
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
static int listener;
#endif
static std::thread worker;
static std::string path;
static size_t received;
extern "C" const char* fixture_begin(int respond) {
    received = 0;
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
#ifdef _WIN32
    path = "\\\\.\\pipe\\oa-server-trust-" + suffix;
    std::wstring wide(path.begin(),path.end());
    listener = CreateNamedPipeW(wide.c_str(),PIPE_ACCESS_DUPLEX,PIPE_TYPE_BYTE|PIPE_WAIT,1,1024,1024,0,nullptr);
    if (listener == INVALID_HANDLE_VALUE) std::abort();
#else
    path = "/tmp/oa-server-trust-" + suffix;
    listener = socket(AF_UNIX,SOCK_STREAM,0);
    sockaddr_un address{}; address.sun_family=AF_UNIX;
    std::memcpy(address.sun_path,path.c_str(),path.size());
    if (listener<0 || bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address)) || listen(listener,1)) std::abort();
#endif
    worker = std::thread([respond] {
#ifdef _WIN32
        if (!ConnectNamedPipe(listener,nullptr) && GetLastError()!=ERROR_PIPE_CONNECTED) return;
        const auto peer=listener;
#else
        const auto peer=accept(listener,nullptr,nullptr);
        if(peer<0)return;
#endif
        char bytes[64];
        for (;;) {
#ifdef _WIN32
            DWORD count=0;
            if(!ReadFile(peer,bytes,sizeof bytes,&count,nullptr) || count==0)break;
#else
            const auto count=recv(peer,bytes,sizeof bytes,0);
            if(count<=0)break;
#endif
            received += count;
            if (respond) {
#ifdef _WIN32
                DWORD sent=0;
                if(!WriteFile(peer,bytes,count,&sent,nullptr) || sent!=count)std::abort();
#else
                if(send(peer,bytes,count,
#ifdef MSG_NOSIGNAL
                    MSG_NOSIGNAL
#else
                    0
#endif
                )!=count)std::abort();
#endif
            }
        }
#ifdef _WIN32
        DisconnectNamedPipe(peer);
#else
        close(peer);
#endif
    });
    return path.c_str();
}
extern "C" size_t fixture_finish() {
    worker.join();
#ifdef _WIN32
    CloseHandle(listener);
#else
    close(listener);unlink(path.c_str());
#endif
    return received;
}
extern "C" const char* fixture_principal() {
    static std::string result;
#ifdef _WIN32
    HANDLE token=nullptr;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))std::abort();
    DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);
    std::vector<unsigned char> buffer(size);
    if(!GetTokenInformation(token,TokenUser,buffer.data(),size,&size))std::abort();
    char* sid=nullptr;
    if(!ConvertSidToStringSidA(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid,&sid))std::abort();
    result=sid;LocalFree(sid);CloseHandle(token);
#else
    result=std::to_string(getuid());
#endif
    return result.c_str();
}
extern "C" const char* fixture_program() {
    static std::string result;
#ifdef _WIN32
    std::vector<wchar_t> wide(32768);
    const auto n=GetModuleFileNameW(nullptr,wide.data(),static_cast<DWORD>(wide.size()));
    if(!n||n>=wide.size())std::abort();
    const auto size=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide.data(),n,nullptr,0,nullptr,nullptr);
    result.resize(size);
    if(!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide.data(),n,result.data(),size,nullptr,nullptr))std::abort();
#elif defined(__linux__)
    std::vector<char> path(32768);
    const auto n=readlink("/proc/self/exe",path.data(),path.size());
    if(n<=0||static_cast<size_t>(n)>=path.size())std::abort();
    result.assign(path.data(),n);
#else
    result="/unsupported/native-proof";
#endif
    return result.c_str();
}
extern "C" size_t fixture_handles() {
#ifdef _WIN32
    DWORD count=0;if(!GetProcessHandleCount(GetCurrentProcess(),&count))std::abort();return count;
#elif defined(__linux__)
    DIR* dir=opendir("/proc/self/fd");if(!dir)std::abort();
    size_t count=0;while(readdir(dir))++count;closedir(dir);return count;
#else
    return 0;
#endif
}

static std::thread signaler;
extern "C" void fixture_cancel_after(oa_ipc_cancellation* cancellation) {
    signaler = std::thread([cancellation] {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        oa_ipc_cancellation_signal(cancellation);
    });
}
extern "C" void fixture_cancel_join() { signaler.join(); }

// Names beside the test image for the file-identity cases (PT-5a): a hard
// link is one file under another name, a rename keeps that file, and a copy
// is another file placed at a name the expectation already uses.
static std::vector<std::string> identity_names;
static std::string identity_name(const char* role) {
    std::string name = fixture_program();
    const auto slash = name.find_last_of("/\\");
    name = name.substr(0, slash + 1) + "oa-guard-" + role + "-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
#ifdef _WIN32
    name += ".exe";
#endif
    identity_names.push_back(name);
    return name;
}
#ifdef _WIN32
static std::wstring widen(const std::string& t) {
    std::wstring w(MultiByteToWideChar(CP_UTF8,0,t.data(),static_cast<int>(t.size()),nullptr,0),L'\0');
    MultiByteToWideChar(CP_UTF8,0,t.data(),static_cast<int>(t.size()),w.data(),static_cast<int>(w.size()));
    return w;
}
#endif
extern "C" const char* fixture_link_self() {
    static std::string result; result = identity_name("link");
#ifdef _WIN32
    if(!CreateHardLinkW(widen(result).c_str(),widen(fixture_program()).c_str(),nullptr))return nullptr;
#else
    if(link(fixture_program(),result.c_str())!=0)return nullptr;
#endif
    return result.c_str();
}
extern "C" const char* fixture_rename(const char* from) {
    static std::string result; result = identity_name("moved");
#ifdef _WIN32
    if(!MoveFileW(widen(from).c_str(),widen(result).c_str()))return nullptr;
#else
    if(rename(from,result.c_str())!=0)return nullptr;
#endif
    return result.c_str();
}
extern "C" int fixture_copy_self_to(const char* name) {
#ifdef _WIN32
    return CopyFileW(widen(fixture_program()).c_str(),widen(name).c_str(),TRUE) ? 1 : 0;
#else
    const int in=open(fixture_program(),O_RDONLY), out=open(name,O_WRONLY|O_CREAT|O_EXCL,0700);
    bool ok=in>=0&&out>=0; char bytes[65536]; ssize_t n=0;
    while(ok&&(n=read(in,bytes,sizeof bytes))>0) ok=write(out,bytes,n)==n;
    if(in>=0)close(in); if(out>=0)close(out);
    return ok&&n==0;
#endif
}
extern "C" void fixture_identity_cleanup() {
    for (const auto& name : identity_names) {
#ifdef _WIN32
        DeleteFileW(widen(name).c_str());
#else
        unlink(name.c_str());
#endif
    }
    identity_names.clear();
}
