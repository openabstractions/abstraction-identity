// Windows Node embedders export Node-API from their own executable.
// Mechanism: node-gyp/src/win_delay_load_hook.cc and Electron's native-module
// documentation. Only an already loaded module is returned; no search is added.
#ifdef _MSC_VER
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <delayimp.h>
#include <cstring>

namespace {
FARPROC WINAPI resolve_node_host(unsigned notification, DelayLoadInfo* import) {
  if (notification != dliNotePreLoadLibrary ||
      _stricmp(import->szDll, OA_NODE_IMPORT_MODULE) != 0) return nullptr;
  HMODULE host = GetModuleHandleW(L"libnode.dll");
  if (!host) host = GetModuleHandleW(nullptr);
  return reinterpret_cast<FARPROC>(host);
}
}
decltype(__pfnDliNotifyHook2) __pfnDliNotifyHook2 = resolve_node_host;
#endif
