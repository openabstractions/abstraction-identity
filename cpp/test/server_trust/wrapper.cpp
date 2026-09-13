#include <abstraction/ipc/frame.hpp>
#include <iostream>
extern "C" const char* fixture_begin(int);
extern "C" size_t fixture_finish();
extern "C" const char* fixture_principal();
extern "C" const char* fixture_program();
int main(){using namespace abstraction::ipc;
#ifdef _WIN32
 const uint32_t kind=OA_IPC_PRINCIPAL_WINDOWS_SID;
#else
 const uint32_t kind=OA_IPC_PRINCIPAL_POSIX_UID;
#endif
 ServerExpectation server{kind,fixture_principal(),fixture_program()};
 auto endpoint=fixture_begin(1);
 auto transport=FrameTransport(endpoint).WithServerExpectation(server);
 server.program="changed caller-owned value";
 try{if(transport.ExchangeFrame("payload")!="payload")return 1;}catch(const FrameError&e){std::cerr<<int(e.status);return 2;}
 if(fixture_finish()!=11)return 3;
 for(int i=0;i<2;++i){
  endpoint=fixture_begin(0);ServerExpectation bad{kind,fixture_principal(),fixture_program()};bad.principal=kind==1?"S-1-0-0":"4294967294";
  auto rejected=FrameTransport(endpoint,Clock::now()+std::chrono::seconds(1)).WithServerExpectation(bad);
  if(i){CancellationSource source;rejected=rejected.WithCancellation(source.Token());}
  try{rejected.ExchangeFrame("private");return 4;}catch(const FrameError&e){if(e.status!=Status::untrusted)return 5;}
  if(fixture_finish()!=0)return 6;
 }
 std::cout<<"PASS verified C++ frame copy and pre-payload refusal\n";
}
