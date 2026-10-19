#include "fileid_private.h"
#include <iostream>
#include <string>
#include <vector>

namespace native = abstraction::identity::fileid_private;
namespace fs = std::filesystem;

// Private test adapter. The Go placetest owner supplies all filesystem fixtures
// and compares these results with the existing FileID implementation.
static int run(const std::vector<fs::path>& args) {
    if (args.size() < 3) return 2;
    try {
        if (args[1] == "leaf" && args.size() == 3) {
            std::cout << native::leaf(args[2]).path().u8string() << '\n';
        } else if (args[1] == "within" && args.size() == 4) {
            auto leaf = native::leaf(args[2]);
            std::cout << (native::within(leaf.folder, args[3]) ? "within" : "outside") << '\n';
        } else {
            return 2;
        }
    } catch (const native::NotLocal&) {
        std::cout << "refused\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
#else
int main(int argc, char** argv) {
#endif
    std::vector<fs::path> args;
    for (int i = 0; i < argc; ++i) args.emplace_back(argv[i]);
    return run(args);
}
