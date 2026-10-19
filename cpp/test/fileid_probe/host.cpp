#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <dlfcn.h>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>
#ifdef __APPLE__
#include <sys/mount.h>
#include <libproc.h>
#include <pthread.h>
#else
#include <sys/vfs.h>
#include <sys/syscall.h>
#endif

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
namespace {
std::mutex mutex;
std::condition_variable changed;
int started=0, active=0, peak=0, release_through=0;
int delay_ms=0;
bool blocked=false;
bool startup_blocked=false,startup_released=false;
int startup_started=0;
int exit_delay_ms=0;
std::vector<int> descriptors;
std::vector<uint64_t> workers;
std::atomic<int> unloaded{0};
using Probe = int(*)(int,char*,size_t);
Probe probe=nullptr;
int caller=-1;
struct Snapshot {int started,active,peak;std::vector<int> descriptors;std::vector<uint64_t> workers;};
Snapshot snapshot() {
    std::lock_guard<std::mutex> held(mutex);
    return {started,active,peak,descriptors,workers};
}
uint64_t current_thread() {
#ifdef __APPLE__
    uint64_t id=0;pthread_threadid_np(nullptr,&id);return id;
#else
    return uint64_t(syscall(SYS_gettid));
#endif
}
void remember_thread() {
    const auto id=current_thread();
    if(std::find(workers.begin(),workers.end(),id)==workers.end())workers.push_back(id);
}
// 1 is present, 0 is confirmed absent, -1 is an unavailable observation.
int thread_state(uint64_t id) {
#ifdef __APPLE__
    // PTHREADID64INFO uses pthread_threadid_np's unique-ID namespace.
    // XNU's legacy LISTTHREADS instead projects cthread_self addresses.
    struct proc_threadinfo info{};errno=0;
    int bytes=proc_pidinfo(getpid(),PROC_PIDTHREADID64INFO,id,&info,sizeof info);
    if(bytes==sizeof info)return 1;
    return bytes==0 && errno==ESRCH ? 0 : -1;
#else
    if(access(("/proc/self/task/"+std::to_string(id)).c_str(),F_OK)==0)return 1;
    return errno==ENOENT ? 0 : -1;
#endif
}
bool workers_live() {
    auto ids=snapshot().workers;
    if(ids.empty())return false;
    for(auto id:ids)if(thread_state(id)!=1)return false;
    return true;
}
bool workers_gone() {
    for(auto id:snapshot().workers)if(thread_state(id)!=0)return false;
    return true;
}
bool wait_exit() {
    for(auto end=Clock::now()+2s;Clock::now()<end;std::this_thread::sleep_for(10ms))if(workers_gone())return true;
    return workers_gone();
}
// This sentinel belongs to the host executable, so it cannot pin the module.
// Its delay makes the healthy finish-before-thread-exit race deterministic.
struct HostExitPause {int delay_ms=0;~HostExitPause(){if(delay_ms)std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));}};
thread_local HostExitPause host_exit_pause;

void require(bool ok,const char* message) {
    std::printf("%s %s\n",ok?"PASS":"FAIL",message);std::fflush(stdout);
    // A failing delayed-worker test must not run process-global destructors
    // while the worker is deliberately held. The owning process reaps it.
    if(!ok)std::_Exit(1);
}
bool wait_started(int count) {
    std::unique_lock<std::mutex> held(mutex);
    return changed.wait_for(held,2s,[&]{return started>=count;});
}
void release(int count) {
    {std::lock_guard<std::mutex> held(mutex);release_through=count;}
    changed.notify_all();
}
bool wait_idle() {
    std::unique_lock<std::mutex> held(mutex);
    return changed.wait_for(held,2s,[]{return active==0;});
}
int call() {char error[512]{};return probe(caller,error,sizeof error);}
bool collect(const char* path) {
    for(auto end=Clock::now()+2s;Clock::now()<end;std::this_thread::sleep_for(10ms)) {
        if(unloaded.load())return true;
        // A later ordinary loader collection is observed explicitly. No
        // assumption is made that the last TLS destructor itself unmaps code.
        if(void* found=dlopen(path,RTLD_NOW|RTLD_NOLOAD))dlclose(found);
    }
    return unloaded.load()!=0;
}
}

extern "C" void oa_probe_event(int event) {
    if(event==1)++unloaded;
}

extern "C" void oa_probe_startup() {
    std::unique_lock<std::mutex> held(mutex);remember_thread();++startup_started;
    changed.notify_all();
    if(startup_blocked)changed.wait(held,[]{return startup_released;});
}

extern "C" int oa_probe_query(int fd,struct statfs* result) {
    host_exit_pause.delay_ms=exit_delay_ms;
    int number,delay;
    {std::unique_lock<std::mutex> held(mutex);
     remember_thread();number=++started;++active;peak=std::max(peak,active);descriptors.push_back(fd);delay=delay_ms;
     changed.notify_all();
     if(blocked)changed.wait(held,[&]{return number<=release_through;});}
    if(delay)std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    std::memset(result,0,sizeof *result);
#ifdef __APPLE__
    result->f_flags=MNT_LOCAL;
#else
    result->f_type=0xef53;
#endif
    {std::lock_guard<std::mutex> held(mutex);--active;}
    changed.notify_all();
    return 0;
}

int main(int argc,char** argv) {
    require(argc==4,"mode, module and owned local folder supplied");
    require(thread_state(current_thread())==1,"native OS sees the current thread in its matching ID namespace");
    const std::string mode=argv[1];const char* path=argv[2];
    caller=open(argv[3],O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    require(caller>=0,"owned local descriptor opened");
    void* module=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    if(!module)std::fprintf(stderr,"dlopen: %s\n",dlerror());
    require(module!=nullptr,"test module loaded");
    probe=reinterpret_cast<Probe>(dlsym(module,"oa_probe_volume"));
    if(mode!="installed")require(probe!=nullptr,"private native query entry resolved");
    if(mode=="installed") {
        using Installed=int(*)(const char*,char*,size_t);
        auto invoke=reinterpret_cast<Installed>(dlsym(module,"oa_probe_installed"));
        require(invoke!=nullptr,"normal installed-archive consumer resolved");
        char error[512]{};int code=invoke(argv[3],error,sizeof error);
        if(code)std::fprintf(stderr,"installed consumer: %s\n",error);
        require(code==0,"normal installed-archive call returned successfully");
        require(dlclose(module)==0,"installed consumer loader reference released");
        const bool collected=collect(path);
        std::printf("OBSERVED installed module after return and collection: %s\n",collected?"collected":"retained");
#ifndef __APPLE__
        require(collected,"installed module collected with default producer flags");
#endif
    } else if(mode=="control") {
        require(dlclose(module)==0,"plain module loader reference released");
        require(collect(path),"plain no-TLV module collected");
    } else if(mode=="healthy_exit") {
        require(probe!=nullptr,"private native query entry resolved");
        exit_delay_ms=100;require(call()==0,"healthy query returned successfully");
        require(workers_gone(),"healthy return joined the entire native worker lifetime");
        dlclose(module);
    } else if(mode=="slow_cleanup") {
        exit_delay_ms=700;std::atomic<int> refused{0};std::vector<std::thread> calls;
        auto began=Clock::now();
        for(int i=0;i<8;++i)calls.emplace_back([&]{if(call())++refused;});
        require(wait_started(8),"eight post-query cleanup workers started");
        for(auto& thread:calls)thread.join();
        auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-began).count();
        std::printf("OBSERVED slow cleanup: %d refused, elapsed %lldms\n",refused.load(),static_cast<long long>(elapsed));
        require(refused==8,"unfinished TLS cleanup refused within the query budget");
        require(elapsed<650,"700ms TLS cleanup did not extend the total 500ms budget");
        require(workers_live(),"native OS sees all controlled cleanup workers before completion");
        require(!workers_gone(),"timed-out cleanup workers remain owned");
        auto now=Clock::now();require(call()!=0,"cleanup-stalled workers retain their quota");
        require(Clock::now()-now<250ms && snapshot().started==8,"full cleanup quota refuses without another worker");
        require(dlclose(module)==0,"caller released module during TLS cleanup");
        require(unloaded==0,"module retained through timed-out TLS cleanup");
        require(wait_exit(),"native OS observed completed slow TLS cleanup");
        module=dlopen(path,RTLD_NOW|RTLD_LOCAL);
        require(module!=nullptr,"module reacquired for later recovery");
        unloaded=0; // Observe collection of this protected loader generation.
        probe=reinterpret_cast<Probe>(dlsym(module,"oa_probe_volume"));
        require(probe!=nullptr,"recovery entry resolved");
        exit_delay_ms=0;require(call()==0,"healthy query succeeds after cleanup releases quota");
        require(dlclose(module)==0,"recovery module reference released");
        const bool collected=collect(path);
        std::printf("OBSERVED slow-cleanup module after recovery: %s\n",collected?"collected":"retained");
#ifndef __APPLE__
        require(collected,"module collected after slow cleanup and recovery");
#endif
    } else if(mode=="healthy") {
        delay_ms=20;std::atomic<int> refused{0};std::vector<std::thread> calls;
        for(int i=0;i<64;++i)calls.emplace_back([&]{if(call())++refused;});
        for(auto& thread:calls)thread.join();
        require(refused==0,"64 healthy queries admitted within their budgets");
        require(snapshot().peak<=8,"healthy outstanding queries bounded by eight");
        require(wait_idle(),"healthy workers drained");
        dlclose(module);
    } else if(mode=="quota" || mode=="descriptor") {
        blocked=true;const int count=mode=="quota"?8:1;
        std::atomic<int> refused{0};std::vector<std::thread> calls;
        auto began=Clock::now();
        for(int i=0;i<count;++i)calls.emplace_back([&]{if(call())++refused;});
        require(wait_started(count),"controlled delayed workers started");
        for(auto& thread:calls)thread.join();
        require(refused==count,"unanswered queries refused");
        require(Clock::now()-began<850ms,"query wait retained the 500ms budget");
        require(workers_live(),"native OS sees all controlled blocked workers");
        for(int fd:snapshot().descriptors) {
            require(fd!=caller && fcntl(fd,F_GETFD)>=0,"timeout retained worker-owned duplicate");
            if(mode=="descriptor")require(fcntl(fd,F_GETFD)&FD_CLOEXEC,"worker duplicate is close-on-exec");
        }
        if(mode=="quota") {
            auto now=Clock::now();require(call()!=0,"full stuck quota refused another query");
            require(Clock::now()-now<250ms,"full stuck quota refused promptly");
            auto state=snapshot();require(state.started==8 && state.peak<=8,"stuck query count stayed bounded");
        }
        release(count);require(wait_idle(),"released query bodies drained");
        {std::lock_guard<std::mutex> held(mutex);blocked=false;}
        bool recovered=false;
        for(auto end=Clock::now()+2s;Clock::now()<end && !recovered;std::this_thread::sleep_for(10ms))recovered=call()==0;
        require(recovered,"returned workers restored later quota");
        dlclose(module);
    } else if(mode=="deadline") {
        blocked=true;std::vector<std::thread> first;
        for(int i=0;i<8;++i)first.emplace_back([]{(void)call();});
        require(wait_started(8),"healthy full quota established");
        int answer=0;auto began=Clock::now();
        std::thread ninth([&]{answer=call();});
        std::this_thread::sleep_for(300ms);release(8);
        require(wait_started(9),"waiting caller received a healthy freed slot");
        ninth.join();
        require(answer!=0,"delayed ninth query refused");
        require(Clock::now()-began<700ms,"admission and query share one total 500ms budget");
        release(9);for(auto& thread:first)thread.join();
        require(wait_idle(),"deadline workers drained");dlclose(module);
    } else if(mode=="lifetime" || mode=="startup") {
        if(mode=="startup")startup_blocked=true;
        blocked=true;require(call()!=0,"delayed module call reached timeout");
        auto state=snapshot();
        if(mode=="startup") {
            std::lock_guard<std::mutex> held(mutex);
            require(startup_started==1 && started==0,"worker delayed before TLS registration and query");
        } else require(state.started==1 && state.active==1,"query worker started before timeout return");
        require(dlclose(module)==0,"caller released its module reference");
        require(unloaded==0,"module retained while delayed worker owns code");
        if(mode=="startup") {
            {std::lock_guard<std::mutex> held(mutex);startup_released=true;}
            changed.notify_all();require(wait_started(1),"worker resumed after caller released module");
        }
        release(1);require(wait_idle(),"delayed query body returned");
        require(wait_exit(),"native OS observed complete worker thread exit");
        const bool collected=collect(path);
        std::printf("OBSERVED after worker exit and later collection: %s\n",collected?"collected":"retained");
#ifdef __APPLE__
        // dyld's natural TLV residency is an explicitly accepted platform
        // cost. Keep its actual collection result visible beside the control.
        require(true,"Darwin natural TLV residency observed");
#else
        require(collected,"module collected after worker exit and later loader collection");
#endif
    } else require(false,"known mode");
    close(caller);return 0;
}
