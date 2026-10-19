#if defined(_WIN32) && (!defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0A00)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include "fileid_private.h"
#include <algorithm>
#include <deque>
#include <system_error>
#include <vector>
#include <cstring>
#include <cwctype>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <fstream>
#include <sstream>
#include <set>
#include <limits>
#include <map>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dlfcn.h>
#ifdef __APPLE__
#include <sys/mount.h>
#include <mach-o/dyld.h>
#else
#include <sys/vfs.h>
#include <link.h>
#endif
#endif

namespace abstraction::fileid {
namespace testing {
void (*before_open)(const fs::path&)=nullptr;
void (*worker_starting)()=nullptr;
}
namespace {
[[noreturn]] void refuse(const fs::path& p,const char* reason){throw NotLocal("identity: "+p.u8string()+": "+reason);}
#ifdef _WIN32
[[noreturn]] void fail(const char* op){throw std::system_error(GetLastError(),std::system_category(),op);}
struct Held {
 HANDLE value=INVALID_HANDLE_VALUE;
 explicit Held(HANDLE h=INVALID_HANDLE_VALUE):value(h){}
 Held(const Held&)=delete;Held& operator=(const Held&)=delete;
 Held(Held&& other)noexcept:value(other.value){other.value=INVALID_HANDLE_VALUE;}
 Held& operator=(Held&& other)noexcept{if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);value=other.value;other.value=INVALID_HANDLE_VALUE;return *this;}
 ~Held(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
};
struct Key {ULONGLONG volume=0;FILE_ID_128 id{};bool wide=true;bool operator==(const Key& o)const{return wide==o.wide&&volume==o.volume&&std::memcmp(id.Identifier,o.id.Identifier,sizeof id.Identifier)==0;}};
Key key(HANDLE h){
 FILE_ID_INFO info{};if(GetFileInformationByHandleEx(h,FileIdInfo,&info,sizeof info))return {info.VolumeSerialNumber,info.FileId,true};
 BY_HANDLE_FILE_INFORMATION legacy{};if(!GetFileInformationByHandle(h,&legacy))fail("folder identity");
 Key out;out.volume=legacy.dwVolumeSerialNumber;out.wide=false;
 auto index=(std::uint64_t(legacy.nFileIndexHigh)<<32)|legacy.nFileIndexLow;
 for(unsigned i=0;i<8;++i)out.id.Identifier[i]=std::uint8_t(index>>(8*i));return out;
}
std::wstring absolute_path(const fs::path& p) {
 auto s=p.wstring();std::replace(s.begin(),s.end(),L'/',L'\\');
 if(s.size()>(std::numeric_limits<USHORT>::max)()/sizeof(wchar_t))refuse(p,"path is not representable by native Unicode length");
 if(s.rfind(L"\\\\?\\",0)==0)return s;
 std::vector<wchar_t> out(32768);auto n=GetFullPathNameW(s.c_str(),DWORD(out.size()),out.data(),nullptr);
 if(!n||n>=out.size())fail("full path");return {out.data(),n};
}
bool device(std::wstring name) {
 name=name.substr(0,name.find_first_of(L".:"));while(!name.empty()&&name.back()==L' ')name.pop_back();
 for(auto& c:name)c=std::towupper(c);
 if(name==L"CON"||name==L"PRN"||name==L"AUX"||name==L"NUL"||name==L"CONIN$"||name==L"CONOUT$")return true;
 return name.size()==4&&(name.substr(0,3)==L"COM"||name.substr(0,3)==L"LPT")&&
  ((name[3]>=L'0'&&name[3]<=L'9')||name[3]==L'\u00b9'||name[3]==L'\u00b2'||name[3]==L'\u00b3');
}
std::pair<std::wstring,std::wstring> volume(std::wstring s,bool link=false) {
 if(s.rfind(L"\\??\\",0)==0)s=L"\\\\?\\"+s.substr(4);
 if(s.rfind(L"\\\\?\\",0)==0)s=s.substr(4);
 if(link&&s.rfind(L"Volume{",0)==0&&s.size()>=44&&s[43]==L'}')return {L"\\\\?\\"+s.substr(0,44)+L"\\",s.size()>44?s.substr(45):L""};
 if(s.size()<3||!iswalpha(s[0])||s[1]!=L':'||s[2]!=L'\\')refuse(fs::path(s),"not a local drive path");
 return {s.substr(0,3),s.substr(3)};
}
fs::path physical_parent(const fs::path& path){auto split=volume(path.wstring(),true);auto at=split.second.find_last_of(L'\\');auto rest=at==std::wstring::npos?L"":split.second.substr(0,at);auto root=split.first;if(root.rfind(L"\\\\?\\",0)!=0)root=L"\\\\?\\"+root;return fs::path(root+rest);}
std::deque<std::wstring> parts(const std::wstring& s) {
 std::deque<std::wstring> out;size_t at=0;
 while(at<s.size()){auto end=s.find(L'\\',at);if(end==std::wstring::npos)end=s.size();if(end>at)out.push_back(s.substr(at,end-at));at=end+1;}return out;
}
void admit(const fs::path& original,const std::wstring& root,const std::wstring& rest) {
 auto kind=GetDriveTypeW(root.c_str());if(kind==DRIVE_REMOTE||kind==DRIVE_UNKNOWN||kind==DRIVE_NO_ROOT_DIR)refuse(original,"not a known local volume");
 for(const auto& name:parts(rest)){
  if(name.size()>(std::numeric_limits<USHORT>::max)()/sizeof(wchar_t))refuse(original,"component is not representable by native Unicode length");
  if(device(name)||name.find_first_of(L":*?<>|\"")!=std::wstring::npos)refuse(original,"device, stream or unsafe component");
 }
}
Held root_handle(const std::wstring& root) {
 auto name=root.rfind(L"\\\\?\\",0)==0?root:L"\\\\?\\"+root;
 if(testing::before_open)testing::before_open(fs::path(name));
 Held h(CreateFileW(name.c_str(),FILE_READ_ATTRIBUTES|SYNCHRONIZE,7,nullptr,OPEN_EXISTING,
  FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr));
 if(h.value==INVALID_HANDLE_VALUE)fail("open root");
 FILE_ATTRIBUTE_TAG_INFO info{};if(!GetFileInformationByHandleEx(h.value,FileAttributeTagInfo,&info,sizeof info))fail("root attributes");
 if(info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)refuse(fs::path(root),"substituted volume root");return h;
}
Held open_at(HANDLE parent,const std::wstring& name,bool create,ACCESS_MASK access=FILE_READ_ATTRIBUTES|SYNCHRONIZE) {
 if(name.size()>(std::numeric_limits<USHORT>::max)()/sizeof(wchar_t))refuse(fs::path(name),"component is not representable by native Unicode length");
 if(testing::before_open)testing::before_open(fs::path(name));
 using NtOpen=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
 static auto open=reinterpret_cast<NtOpen>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtCreateFile"));
 using ToError=ULONG(WINAPI*)(NTSTATUS);static auto to_error=reinterpret_cast<ToError>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlNtStatusToDosError"));
 if(!open||!to_error)throw std::runtime_error("identity: native relative open unavailable");
 UNICODE_STRING text{};text.Buffer=const_cast<wchar_t*>(name.data());text.Length=USHORT(name.size()*2);text.MaximumLength=text.Length;
 SECURITY_QUALITY_OF_SERVICE qos{sizeof(qos),SecurityIdentification,SECURITY_STATIC_TRACKING,FALSE};
 OBJECT_ATTRIBUTES attrs{};attrs.Length=sizeof attrs;attrs.RootDirectory=parent;attrs.ObjectName=&text;attrs.Attributes=OBJ_CASE_INSENSITIVE;attrs.SecurityQualityOfService=&qos;
 IO_STATUS_BLOCK io{};HANDLE h=INVALID_HANDLE_VALUE;
 // No recall, no following a reparse point; all opens are relative to a held folder.
 auto status=open(&h,access,&attrs,&io,nullptr,0,7,create?2:1,
  0x00200000|(create?0:0x00400000)|0x00004000|0x00000020|(create?1:0),nullptr,0);
 if(status<0){SetLastError(to_error(status));fail("open component");}return Held(h);
}
std::wstring final_name(HANDLE h) {
 std::vector<wchar_t> out(32768);auto n=GetFinalPathNameByHandleW(h,out.data(),DWORD(out.size()),FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
 if(!n||n>=out.size())fail("final folder name");return {out.data(),n};
}
std::wstring link_target(HANDLE h,const fs::path& parent,bool relative_only=false) {
 std::vector<unsigned char> data(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);DWORD n=0;
 if(!DeviceIoControl(h,FSCTL_GET_REPARSE_POINT,nullptr,0,data.data(),DWORD(data.size()),&n,nullptr))fail("read link");
 if(n<16)refuse(parent,"short reparse data");DWORD tag=0;std::memcpy(&tag,data.data(),4);
 size_t body=tag==IO_REPARSE_TAG_MOUNT_POINT?16:tag==IO_REPARSE_TAG_SYMLINK?20:0;
 if(!body||n<body)refuse(parent,"unknown link kind");USHORT offset=0,length=0;std::memcpy(&offset,data.data()+8,2);std::memcpy(&length,data.data()+10,2);
 if(offset%2||length%2||body+offset+length>n)refuse(parent,"malformed link");
 std::wstring target(reinterpret_cast<wchar_t*>(data.data()+body+offset),length/2);DWORD flags=0;if(body==20)std::memcpy(&flags,data.data()+16,4);
 if(relative_only){if(!(flags&1)||(!target.empty()&&target[0]==L'\\')||target.find(L':')!=std::wstring::npos)throw ReadEscape("identity: absolute link escapes read parent");return target;}
 if(flags&1){if(!target.empty()&&target[0]==L'\\')target=parent.root_name().wstring()+target;else target=(parent/fs::path(target)).wstring();target=fs::path(target).lexically_normal().wstring();}
 else for(auto& part:parts(target))if(part==L"."||part==L"..")refuse(parent,"absolute link with dot components");
 return target;
}
fs::path walk(const fs::path& original,bool create,Key* identity=nullptr,fs::path* existing=nullptr,Held* retained=nullptr,Held* starting=nullptr,const fs::path& relative=fs::path(),bool=false) {
 const bool confined=starting!=nullptr;
 std::deque<std::wstring> pending;Held current;std::vector<Held> parents;unsigned hops=0;
 if(confined){current=std::move(*starting);pending=parts(relative.native());}
 else {auto split=volume(absolute_path(original));admit(original,split.first,split.second);pending=parts(split.second);current=root_handle(split.first);}
 while(!pending.empty()) {
  auto name=pending.front();pending.pop_front();if(name==L".")continue;
  if(name==L".."){
   if(confined){if(parents.empty())throw ReadEscape("identity: path escapes read parent");current=std::move(parents.back());parents.pop_back();continue;}
   auto here=fs::path(final_name(current.value));if(volume(here.wstring(),true).second.empty())continue;
   auto parent=physical_parent(here);auto dest=volume(parent.wstring(),true);admit(original,dest.first,dest.second);
   auto more=parts(dest.second);more.insert(more.end(),pending.begin(),pending.end());pending=std::move(more);current=root_handle(dest.first);continue;
  }
  Held next;
  if(confined&&(device(name)||name.find(L':')!=std::wstring::npos))throw ReadEscape("identity: device or stream in read parent");
  try{next=open_at(current.value,name,false,confined&&pending.empty()?GENERIC_READ|SYNCHRONIZE:FILE_READ_ATTRIBUTES|SYNCHRONIZE);}catch(const std::system_error& e){
   if(e.code().value()!=ERROR_FILE_NOT_FOUND&&e.code().value()!=ERROR_PATH_NOT_FOUND)throw;
   if(retained)throw;
   if(!create){auto here=fs::path(final_name(current.value));if(identity)*identity=key(current.value);if(existing)*existing=here;auto result=here/name;for(const auto& missing:pending){if(missing==L"..")refuse(original,"parent syntax after missing folder");result/=missing;}return result;}
   next=open_at(current.value,name,true);
  }
  FILE_ATTRIBUTE_TAG_INFO info{};if(!GetFileInformationByHandleEx(next.value,FileAttributeTagInfo,&info,sizeof info))fail("component attributes");
  if((info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)&&(info.ReparseTag&0x20000000)) {
   if(confined){if(++hops>8)throw ReadEscape("identity: too many links in read parent");auto more=parts(link_target(next.value,{},true));more.insert(more.end(),pending.begin(),pending.end());pending=std::move(more);continue;}
   if(++hops>63)refuse(original,"too many links");auto target=link_target(next.value,fs::path(final_name(current.value)));
   auto dest=volume(target,true);admit(original,dest.first,dest.second);auto more=parts(dest.second);more.insert(more.end(),pending.begin(),pending.end());pending=std::move(more);current=root_handle(dest.first);continue;
  }
  if(confined&&pending.empty()){if(retained)*retained=std::move(next);return original;}
  if(!(info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY))throw std::system_error(ERROR_DIRECTORY,std::system_category(),"identity: parent is not a directory");
  if(confined)parents.push_back(std::move(current));current=std::move(next);
 }
 auto result=fs::path(final_name(current.value));if(identity)*identity=key(current.value);if(existing)*existing=result;if(retained)*retained=std::move(current);return result;
}
#else
struct Held {
 int value=-1;explicit Held(int fd=-1):value(fd){}
 Held(const Held&)=delete;Held& operator=(const Held&)=delete;
 Held(Held&& other)noexcept:value(other.value){other.value=-1;}
 Held& operator=(Held&& other)noexcept{if(value>=0)::close(value);value=other.value;other.value=-1;return *this;}
 ~Held(){if(value>=0)::close(value);}
};
struct Key {dev_t device{};ino_t inode{};bool operator==(const Key& o)const{return device==o.device&&inode==o.inode;}};
Key key(int fd){struct stat info{};if(::fstat(fd,&info)!=0)throw std::system_error(errno,std::generic_category(),"folder identity");return {info.st_dev,info.st_ino};}
[[noreturn]] void fail(const char* op){throw std::system_error(errno,std::generic_category(),op);}
fs::path observed(int fd) {
#ifdef __APPLE__
 char name[4096];if(fcntl(fd,F_GETPATH,name)!=0)fail("folder path");return fs::path(name);
#else
 char name[65536];auto link="/proc/self/fd/"+std::to_string(fd);auto n=::readlink(link.c_str(),name,sizeof name);
 if(n<0)fail("folder path");std::string path(name,size_t(n));if(path.size()>=10&&path.substr(path.size()-10)==" (deleted)")throw std::runtime_error("identity: folder removed during walk");return fs::path(path);
#endif
}
// Hold the existing image through worker startup. Its nontrivial TLS then
// owns residency through complete thread teardown, including captured state.
std::shared_ptr<void> startup_residency(const fs::path& path) {
 static const char anchor=0;
 Dl_info image{};
 if(!::dladdr(&anchor,&image)||!image.dli_fname)refuse(path,"module identity unavailable");
#ifdef __APPLE__
 if(image.dli_fbase==_dyld_get_image_header(0))return {};
#else
 struct Main{const void* address;bool contains=false;} main{&anchor};
 ::dl_iterate_phdr([](dl_phdr_info* image,size_t,void* data){
  auto& main=*static_cast<Main*>(data);if(image->dlpi_name&&*image->dlpi_name)return 0;
  auto address=reinterpret_cast<uintptr_t>(main.address);
  for(unsigned i=0;i<image->dlpi_phnum;++i){const auto& segment=image->dlpi_phdr[i];
   auto start=image->dlpi_addr+segment.p_vaddr;
   if(segment.p_type==PT_LOAD&&address>=start&&address-start<segment.p_memsz){main.contains=true;break;}}
  return 1;
 },&main);
 if(main.contains)return {};
#endif
 auto handle=::dlopen(image.dli_fname,RTLD_LAZY|RTLD_LOCAL|RTLD_NOLOAD);
 if(!handle)refuse(path,"module startup residency unavailable");
 return std::shared_ptr<void>(handle,[](void* handle){::dlclose(handle);});
}
// A blocked volume query cannot pin its caller indefinitely. Outstanding
// detached queries are bounded per device and retain their own descriptor.
void volume_local(int fd,const fs::path& path) {
 // Device identity selects only admission accounting; the descriptor query
 // below supplies locality. Healthy bursts share the original 500ms budget.
 struct Answer{bool registered=false,done=false,local=false,stuck=false;int fd=-1;};
 struct Count{unsigned running=0,stuck=0;};
 struct Pool{std::mutex mutex;std::condition_variable changed;std::map<dev_t,Count> devices;};
 static const std::shared_ptr<Pool> owner(new Pool);
 auto pool=owner;
 auto device=key(fd).device;
 auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(500);
 // Avoid GNU_UNIQUE allocation-helper tags that independently prevent ELF
 // module collection. Worker TLS supplies the required temporary residency.
 auto answer=std::shared_ptr<Answer>(new Answer);
 auto residence=startup_residency(path);
 {
  std::unique_lock<std::mutex> held(pool->mutex);
  for(;;){auto& count=pool->devices[device];if(count.running<8){++count.running;break;}
   if(count.stuck||pool->changed.wait_until(held,deadline)==std::cv_status::timeout)refuse(path,"volume query quota exhausted");}
 }
 auto finish=[answer,device,pool]{
  {std::lock_guard<std::mutex> held(pool->mutex);auto& count=pool->devices.at(device);
   --count.running;if(answer->stuck)--count.stuck;answer->done=true;
   if(!count.running)pool->devices.erase(device);}
  pool->changed.notify_all();
 };
 answer->fd=::fcntl(fd,F_DUPFD_CLOEXEC,0);
 if(answer->fd<0){auto error=errno;finish();errno=error;fail("duplicate volume descriptor");}
 std::thread worker;
 try{worker=std::thread([answer,finish,pool,residence]()mutable{
  if(testing::worker_starting)testing::worker_starting();
  // This sentinel precedes query-created TLS. Its teardown follows that
  // cleanup, keeps the quota slot owned, and wakes the caller for a final join.
  struct Residency {decltype(finish) complete;~Residency(){complete();}};
  thread_local Residency residency{finish};
  (void)residency;
  {std::lock_guard<std::mutex> held(pool->mutex);answer->registered=true;}
  pool->changed.notify_all();
  residence.reset();
  struct statfs info{};bool local=::fstatfs(answer->fd,&info)==0;
#ifdef __APPLE__
  local=local&&(info.f_flags&MNT_LOCAL);
#else
  const std::set<unsigned long> remote={0x6969,0x517b,0xff534d42,0xfe534d42,0x00c36400,0x5346414f,0x6b414653,0x01021997,0x73757245,0x564c,0x0bd00bd0,0x47504653,0x19830326,0x01161970,0x7461636f,0xaad7aaea,0xbeefdead,0x013111a8,0x61636673,0x786f4256,0xbacbacbc,0x7c7c6673,0x0187};
  local=local&&!remote.count(static_cast<unsigned long>(info.f_type));
  if(local&&static_cast<unsigned long>(info.f_type)==0x65735546){
   // Bind FUSE classification to the opened descriptor's mount ID, never a
   // different mount sharing its device or a spelling changed during the walk.
   std::ifstream fdinfo("/proc/self/fdinfo/"+std::to_string(answer->fd));std::string line,id;
   while(std::getline(fdinfo,line))if(line.rfind("mnt_id:",0)==0){std::istringstream fields(line.substr(7));fields>>id;}
   local=false;std::ifstream mounts("/proc/self/mountinfo");
   while(!id.empty()&&std::getline(mounts,line)){std::istringstream fields(line);std::string got;fields>>got;if(got!=id)continue;auto separator=line.find(" - ");if(separator==std::string::npos)break;std::istringstream tail(line.substr(separator+3));std::string type;tail>>type;local=type=="fuseblk"||type=="fuse.lxcfs"||type=="fuse.squashfuse"||type=="fuse.squashfuse_ll"||type=="fuse.fuse-overlayfs";break;}
  }
#endif
  ::close(answer->fd);
  {std::lock_guard<std::mutex> held(pool->mutex);answer->local=local;}
 });}catch(...){::close(answer->fd);finish();throw;}
 std::unique_lock<std::mutex> held(pool->mutex);
 if(!pool->changed.wait_until(held,deadline,[&]{return answer->registered&&answer->done;})){
  answer->stuck=true;++pool->devices.at(device).stuck;pool->changed.notify_all();
  held.unlock();worker.detach();refuse(path,"volume query exceeded 500ms");
 }
 held.unlock();worker.join();
 if(!answer->local)refuse(path,"network, unknown FUSE or unavailable volume");
}
std::deque<std::string> parts(const std::string& path){std::deque<std::string> out;size_t at=0;while(at<path.size()){auto end=path.find('/',at);if(end==std::string::npos)end=path.size();if(end>at)out.push_back(path.substr(at,end-at));at=end+1;}return out;}
void candidate_local(const fs::path& path) {
#ifdef __linux__
 // A mount table read does not contact its volumes. Classify a child mount
 // before opening that child; descriptor checks below still own the answer.
 std::ifstream mounts("/proc/self/mountinfo");if(!mounts)refuse(path,"mount table unavailable");
 std::string line,best,type;auto spelling=path.native();
 while(std::getline(mounts,line)) {
  std::istringstream fields(line);std::string id,parent,device,root,mount;fields>>id>>parent>>device>>root>>mount;
  std::string decoded;for(size_t i=0;i<mount.size();++i){if(mount[i]=='\\'&&i+3<mount.size()&&mount[i+1]>='0'&&mount[i+1]<='7'&&mount[i+2]>='0'&&mount[i+2]<='7'&&mount[i+3]>='0'&&mount[i+3]<='7'){decoded.push_back(char((mount[i+1]-'0')*64+(mount[i+2]-'0')*8+mount[i+3]-'0'));i+=3;}else decoded.push_back(mount[i]);}
  if(decoded.empty()||decoded.size()<best.size()||spelling.compare(0,decoded.size(),decoded)!=0||(decoded!="/"&&spelling.size()>decoded.size()&&spelling[decoded.size()]!='/'))continue;
  auto separator=line.find(" - ");if(separator==std::string::npos)refuse(path,"malformed mount table");std::istringstream tail(line.substr(separator+3));tail>>type;best=decoded;
 }
 if(best.empty())refuse(path,"mount identity unavailable");
 const std::set<std::string> remote={"nfs","nfs4","smb","cifs","smb3","ceph","afs","9p","coda","ncp","lustre","gpfs","beegfs","gfs2","ocfs2","panfs","snfs","ibrix","acfs","vboxsf","vmhgfs","prl_fs","autofs"};
 if(remote.count(type))refuse(path,"network or shared mount");
 if(type.rfind("fuse",0)==0&&type!="fuseblk"&&type!="fuse.lxcfs"&&type!="fuse.squashfuse"&&type!="fuse.squashfuse_ll"&&type!="fuse.fuse-overlayfs")refuse(path,"unknown FUSE mount");
#elif defined(__APPLE__)
 int count=::getfsstat(nullptr,0,MNT_NOWAIT);if(count<0)refuse(path,"mount table unavailable");
 std::vector<struct statfs> mounts(size_t(count)+8);int got=::getfsstat(mounts.data(),int(mounts.size()*sizeof(struct statfs)),MNT_NOWAIT);
 if(got<0||size_t(got)>mounts.size())refuse(path,"mount table changed");size_t best=0;bool local=false;auto spelling=path.native();
 for(int i=0;i<got;++i){std::string mount=mounts[i].f_mntonname;if(mount.empty()||mount.size()<best||spelling.compare(0,mount.size(),mount)!=0||(mount!="/"&&spelling.size()>mount.size()&&spelling[mount.size()]!='/'))continue;best=mount.size();local=(mounts[i].f_flags&MNT_LOCAL)!=0;}
 if(!best||!local)refuse(path,"nonlocal or unavailable mount");
#else
 refuse(path,"unsupported native path platform");
#endif
}
fs::path absolute_path(const fs::path& p){if(p.is_absolute())return p;return fs::current_path()/p;}
fs::path walk(const fs::path& original,bool create,Key* identity=nullptr,fs::path* existing=nullptr,Held* retained=nullptr,Held* starting=nullptr,const fs::path& relative=fs::path(),bool nonblocking=false) {
 const bool confined=starting!=nullptr;
 Held current=confined?std::move(*starting):Held(::open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC));if(current.value<0)fail("open root");
 auto pending=parts(confined?relative.native():absolute_path(original).native());unsigned hops=0;std::vector<Held> parents;
 while(!pending.empty()){
  if(!confined)volume_local(current.value,original);auto name=pending.front();pending.pop_front();if(name==".")continue;
  if(confined&&name==".."){if(parents.empty())throw ReadEscape("identity: path escapes read parent");current=std::move(parents.back());parents.pop_back();continue;}
  if(!confined)candidate_local(observed(current.value)/name);struct stat info{};
  if(::fstatat(current.value,name.c_str(),&info,AT_SYMLINK_NOFOLLOW)!=0){if(errno!=ENOENT||retained)fail("stat component");if(!create){auto here=observed(current.value);if(identity)*identity=key(current.value);if(existing)*existing=here;auto result=here/name;for(const auto& missing:pending){if(missing=="..")refuse(original,"parent syntax after missing folder");result/=missing;}return result;}if(::mkdirat(current.value,name.c_str(),0700)!=0&&errno!=EEXIST)fail("create folder");if(::fstatat(current.value,name.c_str(),&info,AT_SYMLINK_NOFOLLOW)!=0)fail("stat new folder");}
  if(S_ISLNK(info.st_mode)){
   if(++hops>(confined?8:40)){if(confined)throw ReadEscape("identity: too many links in read parent");refuse(original,"too many links");}char target[65536];auto n=::readlinkat(current.value,name.c_str(),target,sizeof target);if(n<0)fail("read link");
   std::string text(target,size_t(n));auto next=parts(text);next.insert(next.end(),pending.begin(),pending.end());pending=std::move(next);
   if(!text.empty()&&text[0]=='/'){if(confined)throw ReadEscape("identity: absolute link escapes read parent");current=Held(::open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC));if(current.value<0)fail("restart root");}continue;
  }
  const bool final_file=confined&&pending.empty();
  Held next(::openat(current.value,name.c_str(),O_RDONLY|(final_file?0:O_DIRECTORY)|O_CLOEXEC|O_NOFOLLOW|(final_file&&nonblocking?O_NONBLOCK:0)));if(next.value<0)fail("open component");
  struct stat opened{};if(::fstat(next.value,&opened)!=0)fail("identify folder");
  if(opened.st_dev!=info.st_dev||opened.st_ino!=info.st_ino)throw std::runtime_error("identity: component replaced during walk");
  if(final_file){if(retained)*retained=std::move(next);return original;}
  if(!confined)volume_local(next.value,original);else parents.push_back(std::move(current));current=std::move(next);
 }
 if(!confined)volume_local(current.value,original);auto result=observed(current.value);if(identity)*identity=key(current.value);if(existing)*existing=result;if(retained)*retained=std::move(current);return result;
}
#endif
}
static void spelling_local(const fs::path& p) {
#ifdef _WIN32
 if(p.empty())refuse(p,"empty path");auto raw=p.wstring();if(raw.find(L'\0')!=std::wstring::npos)refuse(p,"NUL in path");
 if(raw.rfind(L"\\??\\",0)==0||raw.rfind(L"\\\\.\\",0)==0||(raw.rfind(L"\\\\",0)==0&&raw.rfind(L"\\\\?\\",0)!=0))refuse(p,"network or device spelling");
 auto split=volume(absolute_path(p));admit(p,split.first,split.second);
#else
 if(p.empty()||p.native().find('\0')!=std::string::npos)refuse(p,"empty or NUL path");
#endif
}
ObjectID identity(std::intptr_t native) {
#ifdef _WIN32
 auto observed=key(reinterpret_cast<HANDLE>(native));ObjectID out;out.format=observed.wide?1:2;out.volume=observed.volume;
 std::copy(std::begin(observed.id.Identifier),std::end(observed.id.Identifier),out.file.begin());return out;
#else
 auto observed=key(int(native));ObjectID out;out.format=3;out.volume=std::uint64_t(observed.device);
 auto inode=std::uint64_t(observed.inode);for(unsigned i=0;i<8;++i)out.file[i]=std::uint8_t(inode>>(8*i));return out;
#endif
}
Opened open_folder(const fs::path& p) {
 spelling_local(p);Held held;walk(p,false,nullptr,nullptr,&held);
#ifdef _WIN32
 auto native=reinterpret_cast<std::intptr_t>(held.value);
#else
 auto native=std::intptr_t(held.value);
#endif
 return Opened(native,std::shared_ptr<Held>(new Held(std::move(held))));
}
EntryID entry_id(const fs::path& p) {
 auto entry=leaf(p);auto parent=open_folder(entry.folder);auto name=entry.name.native();
#ifdef _WIN32
 struct CaseSensitive {ULONG flags;} info{};
 bool sensitive=GetFileInformationByHandleEx(reinterpret_cast<HANDLE>(parent.native_handle()),
     static_cast<FILE_INFO_BY_HANDLE_CLASS>(23),&info,sizeof info) && (info.flags&1);
 if(!sensitive) {
  using Upcase=WCHAR(NTAPI*)(WCHAR);
  static auto upcase=reinterpret_cast<Upcase>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlUpcaseUnicodeChar"));
  if(!upcase)throw std::runtime_error("identity: native filename case table unavailable");
  for(auto& unit:name)unit=upcase(unit);
 }
#endif
 return {identity(parent.native_handle()),std::move(name)};
}
Opened open_read(const fs::path& p,bool confined,bool nonblocking) {
 Held held;
 if(confined) {
  auto parent=p.parent_path();if(parent.empty())parent=fs::path(".");
#ifdef _WIN32
  Held start(CreateFileW(parent.c_str(),FILE_READ_ATTRIBUTES|SYNCHRONIZE,7,nullptr,OPEN_EXISTING,
       FILE_FLAG_BACKUP_SEMANTICS|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr));
  if(start.value==INVALID_HANDLE_VALUE)fail("open read parent");
#else
  Held start(::open(parent.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC));if(start.value<0)fail("open read parent");
#endif
  walk(p,false,nullptr,nullptr,&held,&start,p.filename(),nonblocking);
 } else {
#ifdef _WIN32
  held=Held(CreateFileW(p.c_str(),GENERIC_READ,7,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr));
  if(held.value==INVALID_HANDLE_VALUE)fail("open read file");
#else
  held=Held(::open(p.c_str(),O_RDONLY|O_CLOEXEC|(nonblocking?O_NONBLOCK:0)));if(held.value<0)fail("open read file");
#endif
 }
#ifdef _WIN32
 auto native=reinterpret_cast<std::intptr_t>(held.value);
#else
 auto native=std::intptr_t(held.value);
#endif
 return Opened(native,std::shared_ptr<Held>(new Held(std::move(held))));
}
fs::path folder(const fs::path& p,bool create) {
 spelling_local(p);
#ifdef _WIN32
 return walk(p,create);
#else
 return walk(p,create);
#endif
}
Leaf leaf(const fs::path& p,bool create) {
 spelling_local(p);
#ifdef _WIN32
 auto abs=fs::path(absolute_path(p));auto name=abs.filename().wstring();if(p.wstring().rfind(L"\\\\?\\",0)!=0)while(!name.empty()&&(name.back()==L'.'||name.back()==L' '))name.pop_back();if(name.empty()||name==L"."||name==L"..")refuse(p,"not a leaf");
 auto parent=folder(abs.parent_path(),create);
 // Query the directory entry's long name, without following a leaf link. An
 // absent 8.3-shaped leaf stays as supplied; replacement replaces that entry.
 if(name.find(L'~')!=std::wstring::npos){
  WIN32_FIND_DATAW found{};auto search=FindFirstFileW((parent/fs::path(name)).c_str(),&found);
  if(search!=INVALID_HANDLE_VALUE){FindClose(search);name=found.cFileName;}
  else if(GetLastError()!=ERROR_FILE_NOT_FOUND&&GetLastError()!=ERROR_PATH_NOT_FOUND)fail("leaf alias");
 }
 return {parent,fs::path(name)};
#else
 auto abs=absolute_path(p);auto name=abs.filename();if(name.empty()||name=="."||name=="..")refuse(p,"not a leaf");return {folder(abs.parent_path(),create),name};
#endif
}
std::optional<fs::path> within(const fs::path& p,const fs::path& root) {
 spelling_local(p);spelling_local(root);Key wanted{},current{};fs::path root_existing,ancestor;
 auto parent=walk(root,false,&wanted,&root_existing);if(parent!=root_existing)throw std::runtime_error("identity: containment root is missing");
 auto child=walk(p,false,&current,&ancestor);
 // Names supply only the relative spelling after native folder identity has
 // established ancestry; a lexical prefix never supplies containment proof.
 for(;;){if(current==wanted){auto rel=child.lexically_relative(ancestor);return rel.empty()?fs::path("."):rel;}
#ifdef _WIN32
  if(volume(ancestor.wstring(),true).second.empty())return std::nullopt;
#else
  if(ancestor==ancestor.root_path())return std::nullopt;
#endif
#ifdef _WIN32
  auto up=physical_parent(ancestor);
#else
  auto up=ancestor.parent_path();
#endif
  if(up==ancestor||up.empty())return std::nullopt;
  ancestor=walk(up,false,&current,nullptr);
 }
}
void local(const fs::path& p) {
 spelling_local(p);
 try { (void)folder(p,false); }
 catch(const std::system_error& error) {
#ifdef _WIN32
  if(error.code().value()!=ERROR_DIRECTORY)throw;
#else
  if(error.code()!=std::errc::not_a_directory)throw;
#endif
  (void)leaf(p,false);
 }
}
}
