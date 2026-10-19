#pragma once
// Source-only conformance seams, never installed. Product declarations and the
// separately linkable implementation belong to the existing Identity SDK.
#include <abstraction/fileid.h>
namespace abstraction::fileid {
namespace testing {
extern void (*before_open)(const fs::path&);
extern void (*worker_starting)();
}
}
namespace abstraction::identity { namespace fileid_private = ::abstraction::fileid; }
