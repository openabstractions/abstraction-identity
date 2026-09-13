#pragma once
#ifdef __linux__
#include "local_stream.h"
#include <abstraction/ipc/client.h>
#include <cstdlib>
#include <map>
#include <linux/sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
extern char **environ;

namespace abstraction::ipc_internal::linux_selection {
inline oa_ipc_status budget(local_stream::Deadline deadline, local_stream::Cancellation* cancel) {
    if(cancel && cancel->requested())return OA_IPC_CANCELLED;
    return local_stream::Clock::now()>=deadline?OA_IPC_TIMEOUT:OA_IPC_OK;
}
// clone3 returns a stable process handle atomically. An embedding application's
// concurrent child reaper cannot redirect cancellation to a recycled PID.
struct Child {
    int handle=-1, reader=-1;
    ~Child() {
        if(reader>=0)::close(reader);
        if(handle>=0) {
            ::syscall(SYS_pidfd_send_signal,handle,SIGKILL,nullptr,0);
            pollfd stopped{handle,POLLIN,0};
            while(::poll(&stopped,1,-1)<0 && errno==EINTR) {}
            siginfo_t info{};
            while(::waitid(P_PIDFD,handle,&info,WEXITED)<0 && errno==EINTR) {}
            ::close(handle);
        }
    }
};

inline oa_ipc_status query(std::string& out, local_stream::Deadline deadline,
    local_stream::Cancellation* cancel, const char* executable="/usr/bin/systemctl") {
    auto state=budget(deadline,cancel);if(state!=OA_IPC_OK)return state;
    int pipes[2];if(::pipe2(pipes,O_CLOEXEC))return OA_IPC_IO_ERROR;
    if(::fcntl(pipes[0],F_SETFL,O_NONBLOCK)<0){::close(pipes[0]);::close(pipes[1]);return OA_IPC_IO_ERROR;}
    for(int& fd:pipes)if(fd<=STDERR_FILENO) {
        int replacement=::fcntl(fd,F_DUPFD_CLOEXEC,3);
        if(replacement<0){::close(pipes[0]);::close(pipes[1]);return OA_IPC_IO_ERROR;}
        ::close(fd);fd=replacement;
    }
    Child child;child.reader=pipes[0];
    const char* args[]={executable,"--user","show","abstraction-runtime.service",
        "--property=LoadState,ExecStart,User","--no-pager",nullptr};
    clone_args options{};
    options.flags=CLONE_PIDFD;options.exit_signal=SIGCHLD;
    options.pidfd=reinterpret_cast<uint64_t>(&child.handle);
    const auto spawned=::syscall(SYS_clone3,&options,sizeof options);
    if(spawned==0) {
        if(::dup2(pipes[1],STDOUT_FILENO)<0 || ::dup2(pipes[1],STDERR_FILENO)<0)::_exit(127);
        ::close(pipes[0]);::close(pipes[1]);
        ::execve(executable,const_cast<char* const*>(args),environ);
        ::_exit(127);
    }
    ::close(pipes[1]);
    if(spawned<0)return OA_IPC_PROOF_UNAVAILABLE;
    out.clear();bool eof=false;
    for(;;) {
        state=budget(deadline,cancel);if(state!=OA_IPC_OK)return state;
        if(!eof) {
            char buffer[4096];const auto count=::read(child.reader,buffer,sizeof buffer);
            if(count>0) {
                if(out.size()+static_cast<size_t>(count)>65536)return OA_IPC_UNTRUSTED;
                out.append(buffer,static_cast<size_t>(count));continue;
            }
            if(count==0)eof=true;
            else if(errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)return OA_IPC_IO_ERROR;
        }
        siginfo_t info{};
        if(::waitid(P_PIDFD,child.handle,&info,WEXITED|WNOHANG|WNOWAIT)<0) {
            if(errno==EINTR)continue;
            return OA_IPC_IO_ERROR;
        }
        if(eof && info.si_pid) {
            if(info.si_code!=CLD_EXITED || info.si_status!=0)return OA_IPC_UNTRUSTED;
            return budget(deadline,cancel);
        }
        pollfd fds[3]{{eof?-1:child.reader,POLLIN,0},{cancel?cancel->wake():-1,POLLIN,0},{info.si_pid?-1:child.handle,POLLIN,0}};
        if(::poll(fds,3,local_stream::detail::remaining_ms(deadline))<0 && errno!=EINTR)return OA_IPC_IO_ERROR;
    }
}

inline bool decode_path(const std::string& text,std::string& out) {
    out.clear();
    auto digit=[](char c)->int {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
    for(size_t i=0;i<text.size();++i) {
        if(text[i]!='\\') {out+=text[i];continue;}
        if(++i==text.size())return false;
        char c=text[i];
        if(c=='\\'||c=='"') {out+=c;continue;}
        const std::string keys="abfnrtv", values="\a\b\f\n\r\t\v";
        auto at=keys.find(c);if(at!=std::string::npos){out+=values[at];continue;}
        unsigned value=0;size_t n=0;unsigned base=16;
        if(c=='x')n=2;else if(c=='u')n=4;else if(c=='U')n=8;
        else if(c>='0'&&c<='7'){n=3;base=8;--i;}else return false;
        if(n>text.size()-i-1)return false;
        for(size_t j=0;j<n;++j){int d=digit(text[++i]);if(d<0||unsigned(d)>=base)return false;value=value*base+unsigned(d);}
        if(base==8&&value>255)return false;
        if(c=='x'||base==8)out+=static_cast<char>(value);
        else {
            if(value>0x10ffff || (value>=0xd800&&value<=0xdfff))return false;
            if(value<0x80)out+=static_cast<char>(value);
            else if(value<0x800){out+=char(0xc0|(value>>6));out+=char(0x80|(value&63));}
            else if(value<0x10000){out+=char(0xe0|(value>>12));out+=char(0x80|((value>>6)&63));out+=char(0x80|(value&63));}
            else{out+=char(0xf0|(value>>18));out+=char(0x80|((value>>12)&63));out+=char(0x80|((value>>6)&63));out+=char(0x80|(value&63));}
        }
    }
    return true;
}

inline bool program(const std::string& output,std::string& path) {
    std::string text=output;if(!text.empty()&&text.back()=='\n')text.pop_back();
    std::map<std::string,std::string> fields;
    size_t pos=0;
    do {
        auto end=text.find('\n',pos);auto line=text.substr(pos,end==std::string::npos?end:end-pos);
        auto eq=line.find('=');if(eq==std::string::npos)return false;
        auto key=line.substr(0,eq);
        if(key!="LoadState"&&key!="ExecStart"&&key!="User")return false;
        if(!fields.emplace(key,line.substr(eq+1)).second)return false;
        if(end==std::string::npos)break;
        pos=end+1;
    }while(true);
    if(fields.size()!=3||fields["LoadState"]!="loaded"||!fields["User"].empty())return false;
    auto entry=fields["ExecStart"];
    if(entry.compare(0,7,"{ path=")||entry.size()<9||entry.substr(entry.size()-2)!=" }"||entry.find("{ path=",7)!=std::string::npos)return false;
    auto split=entry.find(" ; argv[]=",7);
    if(split==std::string::npos||entry.find(" ; ignore_errors=no ; ",split+10)==std::string::npos)return false;
    if(!decode_path(entry.substr(7,split-7),path)||path.empty()||path[0]!='/'||path.find_first_of(std::string("\0\r\n",3))!=std::string::npos)return false;
    if(path.size()>1&&path.back()=='/')return false;
    pos=1;
    while(pos<path.size()) {
        auto end=path.find('/',pos);auto part=path.substr(pos,end==std::string::npos?end:end-pos);
        if(part.empty()||part=="."||part=="..")return false;
        if(end==std::string::npos)break;
        pos=end+1;
    }
    return true;
}
}
#endif
