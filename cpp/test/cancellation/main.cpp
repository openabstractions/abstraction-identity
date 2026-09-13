#include <abstraction/ipc/frame.hpp>
#include <condition_variable>
#include <cstring>
#include <future>
#include <iostream>
#include <mutex>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif
using namespace abstraction::ipc;
using namespace std::chrono_literals;
extern "C" const char* fixture_start();
extern "C" int fixture_finish();
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
// Local fixture holds a connected peer without reading or writing.
class QuietPeer {
public:
    std::string path;
    QuietPeer() {
        const auto suffix = std::to_string(Clock::now().time_since_epoch().count());
#ifdef _WIN32
        path = "\\\\.\\pipe\\oa-cancel-" + suffix;
        std::wstring wide(path.begin(),path.end());
        listener = CreateNamedPipeW(wide.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE|PIPE_WAIT, 1, 1024,1024,0,nullptr);
        require(listener!=INVALID_HANDLE_VALUE,"fixture pipe");
#else
        path="/tmp/oa-cancel-"+suffix;
        listener=socket(AF_UNIX,SOCK_STREAM,0);
        sockaddr_un addr{};addr.sun_family=AF_UNIX;std::memcpy(addr.sun_path,path.c_str(),path.size());
        require(listener>=0 && !bind(listener,reinterpret_cast<sockaddr*>(&addr),sizeof(addr)) && !listen(listener,1),"fixture socket");
#endif
        worker=std::thread([this]{
#ifdef _WIN32
            require(ConnectNamedPipe(listener,nullptr) || GetLastError()==ERROR_PIPE_CONNECTED,"fixture accept");
#else
            const int peer=accept(listener,nullptr,nullptr);require(peer>=0,"fixture accept");
#endif
            {std::unique_lock<std::mutex> lock(mu);connected=true;cv.notify_all();cv.wait(lock,[this]{return release;});}
#ifdef _WIN32
            DisconnectNamedPipe(listener);
#else
            close(peer);
#endif
        });
    }
    void Accepted(){std::unique_lock<std::mutex> lock(mu);require(cv.wait_for(lock,2s,[this]{return connected;}),"connection absent");}
    ~QuietPeer(){
        {std::lock_guard<std::mutex> lock(mu);release=true;}cv.notify_all();worker.join();
#ifdef _WIN32
        CloseHandle(listener);
#else
        close(listener);unlink(path.c_str());
#endif
    }
private:
#ifdef _WIN32
    HANDLE listener;
#else
    int listener;
#endif
    std::thread worker;std::mutex mu;std::condition_variable cv;bool connected=false,release=false;
};
int main(){try{
    CancellationSource cancelled;cancelled.Cancel();cancelled.Cancel();
#ifdef _WIN32
    FrameTransport absent(R"(\\.\pipe\oa-cancel-absent)",5000);
#else
    FrameTransport absent("/tmp/oa-cancel-absent",5000);
#endif
    auto refused=absent.WithCancellation(cancelled.Token());
    try{refused.ExchangeFrame("x");require(false,"cancelled open succeeded");}
    catch(const FrameError& e){require(e.status==Status::cancelled,"cancelled open lost status");}
    for(bool writing:{false,true}){
        QuietPeer peer;CancellationSource source;
        Stream stream(peer.path,Clock::now()+5s,source.Token());require(stream.valid(),"open");peer.Accepted();
        auto waiting=std::async(std::launch::async,[&]{
            if(writing){std::string bytes(16*1024*1024,'x');return stream.write_all(bytes);}
            char byte;size_t moved;return stream.read_some(&byte,1,moved);
        });
        require(waiting.wait_for(50ms)==std::future_status::timeout,"fixture did not hold IO");
        source.Cancel();
        require(waiting.wait_for(1s)==std::future_status::ready,"cancelled IO stayed blocked");
        require(!waiting.get() && stream.status()==Status::cancelled,"IO cancellation status");
    }
    // The unmodified transport and a new token retain normal operation.
    for(bool token:{false,true}){
        FrameTransport ordinary(fixture_start(),2000);
        auto preCancelled=ordinary.WithCancellation(cancelled.Token());
        try{preCancelled.ExchangeFrame("abc");require(false,"cancelled copy reached peer");}
        catch(const FrameError& e){require(e.status==Status::cancelled,"cancelled copy status");}
        CancellationSource source;
        auto operation=token?ordinary.WithCancellation(source.Token()):ordinary;
        require(operation.ExchangeFrame("abc")=="abc","fresh exchange");
        require(fixture_finish(),"echo fixture");
    }
    // Native connection retains cancellation state after the handle is released.
    const std::string endpoint=fixture_start();oa_ipc_cancellation* raw=nullptr;
    require(oa_ipc_cancellation_create(&raw)==OA_IPC_OK,"C token create");
    oa_ipc_connection* connection=nullptr;
    require(oa_ipc_open_cancelable(endpoint.data(),endpoint.size(),2000,raw,&connection)==OA_IPC_OK,"C open");
    oa_ipc_cancellation_release(raw);
    const char frame[7]={0,0,0,3,'a','b','c'};size_t moved=0;
    require(oa_ipc_write(connection,frame,7,&moved)==OA_IPC_OK && moved==7,"write after token release");
    char reply[7];size_t total=0;
    while(total<7){require(oa_ipc_read(connection,reply+total,7-total,&moved)==OA_IPC_OK && moved,"read after token release");total+=moved;}
    oa_ipc_close(connection);
    require(!std::memcmp(frame,reply,7) && fixture_finish(),"C retained state echo");
    std::cout<<"cancellation open/read/write, fresh reuse and C handle lifetime passed\n";
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
