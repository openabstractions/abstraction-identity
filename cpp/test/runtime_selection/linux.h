#pragma once
#ifdef __linux__
#include <thread>
#include <iostream>
#include <cassert>
inline void selection_reaper(int) {
    int saved=errno,status;
    while(::waitpid(-1,&status,WNOHANG)>0) {}
    errno=saved;
}
inline std::string unit(const std::string& path) {
    return "LoadState=loaded\nUser=\nExecStart={ path="+path+" ; argv[]="+path+" serve runtime ; ignore_errors=no ; start_time=[n/a] }\n";
}
inline int linux_helper(int argc,char** argv) {
    if(argc!=6 || std::string(argv[1])!="--user" || std::string(argv[2])!="show" ||
       std::string(argv[3])!="abstraction-runtime.service" || std::string(argv[4])!="--property=LoadState,ExecStart,User" || std::string(argv[5])!="--no-pager")return 8;
    std::string mode=::getenv("OA_SELECTION_TEST_MODE");
    if(mode=="ok"){std::cout<<unit("/bin/sh");return 0;}
    if(mode=="failure"){std::cout<<unit("/bin/sh");return 7;}
    if(mode=="large"){std::cout<<std::string(70000,'x');return 0;}
    std::cout<<::getpid()<<std::endl;
    if(mode=="closed"){::close(1);::close(2);}
    for(;;)::pause();
}
inline void linux_tests() {
    using namespace abstraction;
    using namespace ipc_internal;
    std::string path;
    require(linux_selection::program(unit("/bin/sh"),path)&&path=="/bin/sh","loaded program");
    require(linux_selection::program(unit("/space\\x20name/run"),path)&&path=="/space name/run","hex path escape");
    require(linux_selection::program(unit("/\\u00e9/\\101"),path)&&path=="/\xc3\xa9/A","unicode octal escape");
    for(const auto& bad:{std::string("relative"),std::string("/x/../y"),std::string("/x//y"),std::string("/x/"),std::string("/x\\x00z"),std::string("/x\\uD800"),std::string("/x\\q")})
        require(!linux_selection::program(unit(bad),path),"invalid program accepted");
    for(auto bad:{unit("/bin/sh")+"User=\n",std::string("LoadState=not-found\nUser=\nExecStart=\n"),std::string("LoadState=loaded\nUser=root\nExecStart=\n"),unit("/bin/sh")+"\n"})
        require(!linux_selection::program(bad,path),"invalid unit accepted");
    auto multiple=unit("/bin/sh");multiple.insert(multiple.size()-1," { path=/bin/sh }");
    require(!linux_selection::program(multiple,path),"multiple executable accepted");
    auto deadline=[](){return local_stream::Clock::now()+std::chrono::seconds(1);};
    std::string output;
    ::setenv("OA_SELECTION_TEST_MODE","ok",1);
    require(linux_selection::query(output,deadline(),nullptr,"/proc/self/exe")==OA_IPC_OK&&output==unit("/bin/sh"),"helper query");
    RuntimeIdentity selected;
    require(select_linux_runtime(selected,deadline(),nullptr,"/proc/self/exe")==OA_IPC_OK,"selected unit identity");
    char* canonical=::realpath("/bin/sh",nullptr);
    require(canonical && selected.program==canonical && selected.kind==OA_IPC_PRINCIPAL_POSIX_UID && selected.principal==std::to_string(::geteuid()),"selected principal/program");
    ::free(canonical);
    require(linux_selection::query(output,deadline(),nullptr,"/nonexistent/oa-helper")==OA_IPC_UNTRUSTED,"missing helper");
    ::setenv("OA_SELECTION_TEST_MODE","failure",1);
    require(linux_selection::query(output,deadline(),nullptr,"/proc/self/exe")==OA_IPC_UNTRUSTED,"exit failure");
    ::setenv("OA_SELECTION_TEST_MODE","large",1);
    require(linux_selection::query(output,deadline(),nullptr,"/proc/self/exe")==OA_IPC_UNTRUSTED,"output bound");
    for(auto mode:{"stall","closed"}) {
        ::setenv("OA_SELECTION_TEST_MODE",mode,1);
        auto start=local_stream::Clock::now();
        require(linux_selection::query(output,start+std::chrono::milliseconds(80),nullptr,"/proc/self/exe")==OA_IPC_TIMEOUT,"deadline");
        require(local_stream::Clock::now()-start<std::chrono::seconds(1),"deadline was extended");
        int pid=std::stoi(output);int status;
        require(::waitpid(pid,&status,WNOHANG)==-1&&errno==ECHILD,"helper not reaped");
        require(::kill(pid,0)==-1&&errno==ESRCH,"helper survived");
    }
    ::setenv("OA_SELECTION_TEST_MODE","stall",1);
    local_stream::Cancellation cancellation;
    std::thread signal([&]{std::this_thread::sleep_for(std::chrono::milliseconds(30));cancellation.signal();});
    auto state=linux_selection::query(output,deadline(),&cancellation,"/proc/self/exe");signal.join();
    require(state==OA_IPC_CANCELLED,"cancellation");
    require(::kill(std::stoi(output),0)==-1&&errno==ESRCH,"cancelled helper survived");
    struct Restore {
        struct sigaction original{};
        Restore(){::sigaction(SIGCHLD,nullptr,&original);}
        ~Restore(){::sigaction(SIGCHLD,&original,nullptr);}
    } restore;
    struct sigaction action{};action.sa_handler=selection_reaper;::sigemptyset(&action.sa_mask);
    require(::sigaction(SIGCHLD,&action,nullptr)==0,"install fixture child reaper");
    ::setenv("OA_SELECTION_TEST_MODE","ok",1);
    auto reaped=linux_selection::query(output,deadline(),nullptr,"/proc/self/exe");
    require(reaped==OA_IPC_IO_ERROR||reaped==OA_IPC_OK,"competing reaper result");
    action.sa_handler=SIG_IGN;
    require(::sigaction(SIGCHLD,&action,nullptr)==0,"install fixture auto reaper");
    require(linux_selection::query(output,deadline(),nullptr,"/proc/self/exe")==OA_IPC_IO_ERROR,"auto reaper refuses lost status");
    ::unsetenv("OA_SELECTION_TEST_MODE");
}
#endif
