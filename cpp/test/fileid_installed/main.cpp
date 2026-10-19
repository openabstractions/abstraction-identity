#include <abstraction/fileid.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
namespace fs=std::filesystem;
int main() {
    auto base=fs::temp_directory_path()/fs::path("oa-fileid-sdk-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    struct Owned {fs::path p;~Owned(){std::error_code ignored;fs::remove_all(p,ignored);}} owned{base};
    try {
        auto root=abstraction::fileid::folder(base,true);
        auto value=abstraction::fileid::leaf(root/"pending"/"record");
        auto rel=abstraction::fileid::within(value.folder,root);
        if(!rel||*rel!="pending")return 1;
        abstraction::fileid::folder(value.folder,true);
        std::ofstream(value.path())<<"content";
        abstraction::fileid::local(value.path());
        auto same=abstraction::fileid::within(value.folder,value.folder);
        if(!same||*same!=".")return 2;
        if(abstraction::fileid::within(root,value.folder))return 3;
        std::cout<<"installed FileID independently resolves pending and existing local paths\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<"\n";return 4;}
}
