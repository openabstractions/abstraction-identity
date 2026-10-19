#include <abstraction/fileid.h>
#ifdef OA_PROBE_CAS
#include <abstraction/cas.h>
#endif
#include <cstdio>
#include <stdexcept>
extern "C" void oa_probe_event(int);
namespace {struct Lifetime {~Lifetime(){oa_probe_event(1);}} lifetime;}
extern "C" int oa_probe_installed(const char* folder,char* error,size_t size) {
    try {
        auto root=abstraction::fileid::folder(folder);
        (void)abstraction::fileid::leaf(root/"pending");
#ifdef OA_PROBE_CAS
        auto path=root/"native-installed-consumer";
        abstraction::cas::change(path,[](const abstraction::cas::Value&){return std::string("ready");});
        if(abstraction::cas::read(path)!=abstraction::cas::Value("ready"))throw std::runtime_error("installed CAS value differs");
#endif
        return 0;
    } catch(const std::exception& e) {std::snprintf(error,size,"%s",e.what());return 1;}
}
