#include <abstraction/discovery/client.h>
#include <abstraction/ipc/client.hpp>
int main() {
    abstraction::ipc::Stream expired("unused", abstraction::ipc::Clock::now());
    return expired.status() == abstraction::ipc::Status::timeout &&
           abstraction::discovery::endpoint_path("probe").size() > 5 ? 0 : 1;
}
