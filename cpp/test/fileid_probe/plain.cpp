#include <cstddef>
extern "C" void oa_probe_event(int);
namespace {struct Lifetime {~Lifetime(){oa_probe_event(1);}} lifetime;}
extern "C" int oa_probe_volume(int,char*,std::size_t){return 0;}
