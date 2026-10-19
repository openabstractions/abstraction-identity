#include <abstraction/ipc/client.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#endif
const char* fixture_start(void);
int fixture_finish(void);
static int failures;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); ++failures; } } while (0)
static void endpoint_env(const char* value) {
#ifdef _WIN32
    CHECK(_putenv_s("ABSTRACTION_RUNTIME_ENDPOINT",value)==0);
#else
    CHECK(setenv("ABSTRACTION_RUNTIME_ENDPOINT",value,1)==0);
#endif
}
#ifdef _WIN32
static void windows_process_environment_test(void) {
    static const wchar_t name[]=L"ABSTRACTION_RUNTIME_ENDPOINT";
    char baseline[512],changed[512];size_t required=0;
    CHECK(SetEnvironmentVariableW(name,NULL));
    CHECK(oa_ipc_runtime_endpoint(baseline,sizeof baseline,&required)==OA_IPC_OK);
    /* Seed the caller CRT, then update only the actual process block. A DLL
       with its own /MT CRT and a same-CRT caller must both read the OS value. */
    CHECK(_putenv_s("ABSTRACTION_RUNTIME_ENDPOINT","crt-local-seed")==0);
    CHECK(SetEnvironmentVariableW(name,L"os-process-change"));
    CHECK(oa_ipc_runtime_endpoint(changed,sizeof changed,&required)==OA_IPC_OK && strcmp(changed,"os-process-change")==0);
    CHECK(SetEnvironmentVariableW(name,L""));
    CHECK(oa_ipc_runtime_endpoint(changed,sizeof changed,&required)==OA_IPC_OK && strcmp(changed,baseline)==0);
    CHECK(SetEnvironmentVariableW(name,NULL));
    CHECK(oa_ipc_runtime_endpoint(changed,sizeof changed,&required)==OA_IPC_OK && strcmp(changed,baseline)==0);
    {
        wchar_t value[16005];char expected[16010],actual[16010];size_t i;
        for(i=0;i<16000;++i){value[i]=L'x';expected[i]='x';}
        value[16000]=0x03bb;value[16001]=0x96ea;value[16002]=0xd83d;value[16003]=0xde00;value[16004]=0;
        memcpy(expected+16000,"\xce\xbb\xe9\x9b\xaa\xf0\x9f\x98\x80",10);
        CHECK(SetEnvironmentVariableW(name,value));
        CHECK(oa_ipc_runtime_endpoint(NULL,0,&required)==OA_IPC_OK && required==sizeof expected);
        memset(actual,'!',sizeof actual);
        CHECK(oa_ipc_runtime_endpoint(actual,1,&required)==OA_IPC_INVALID_ARGUMENT && required==sizeof expected && actual[0]=='!');
        CHECK(oa_ipc_runtime_endpoint(actual,sizeof actual,&required)==OA_IPC_OK && memcmp(actual,expected,sizeof actual)==0);
    }
    CHECK(SetEnvironmentVariableW(name,NULL));
    CHECK(oa_ipc_runtime_endpoint(changed,sizeof changed,&required)==OA_IPC_OK && strcmp(changed,baseline)==0);
}
#endif
static void bootstrap_test(void) {
    size_t required=99;
    char buffer[512]; memset(buffer,'!',sizeof buffer);
    CHECK(oa_ipc_runtime_endpoint(NULL,0,NULL)==OA_IPC_INVALID_ARGUMENT);
    CHECK(oa_ipc_runtime_endpoint(NULL,1,&required)==OA_IPC_INVALID_ARGUMENT && required==0);
    CHECK(oa_ipc_runtime_endpoint(buffer,0,&required)==OA_IPC_INVALID_ARGUMENT && required==0);
    endpoint_env("explicit-bootstrap");
#ifdef __APPLE__
    /* bootstrap.hpp and RuntimeSelection bind installed Darwin selection to
       this fixed Mach service, independently of the environment override. */
    static const char expected[]="xpc:com.openabstractions.runtime-v1";
    CHECK(oa_ipc_runtime_endpoint(NULL,0,&required)==OA_IPC_OK && required==sizeof expected);
    CHECK(oa_ipc_runtime_endpoint(buffer,1,&required)==OA_IPC_INVALID_ARGUMENT && required==sizeof expected && buffer[0]=='!');
    CHECK(oa_ipc_runtime_endpoint(buffer,required,&required)==OA_IPC_OK && strcmp(buffer,expected)==0);
    endpoint_env("a-longer-explicit-bootstrap");
    CHECK(oa_ipc_runtime_endpoint(buffer,sizeof expected-1,&required)==OA_IPC_INVALID_ARGUMENT && required==sizeof expected);
    CHECK(strcmp(buffer,expected)==0);
    CHECK(oa_ipc_runtime_endpoint(buffer,sizeof buffer,&required)==OA_IPC_OK && strcmp(buffer,expected)==0);
#else
    CHECK(oa_ipc_runtime_endpoint(NULL,0,&required)==OA_IPC_OK && required==19);
    CHECK(oa_ipc_runtime_endpoint(buffer,1,&required)==OA_IPC_INVALID_ARGUMENT && required==19 && buffer[0]=='!');
    CHECK(oa_ipc_runtime_endpoint(buffer,required,&required)==OA_IPC_OK && strcmp(buffer,"explicit-bootstrap")==0);
    endpoint_env("a-longer-explicit-bootstrap");
    CHECK(oa_ipc_runtime_endpoint(buffer,19,&required)==OA_IPC_INVALID_ARGUMENT && required==28);
    CHECK(strcmp(buffer,"explicit-bootstrap")==0);
    CHECK(oa_ipc_runtime_endpoint(buffer,sizeof buffer,&required)==OA_IPC_OK && strcmp(buffer,"a-longer-explicit-bootstrap")==0);
#endif
    endpoint_env("");
    CHECK(oa_ipc_runtime_endpoint(buffer,sizeof buffer,&required)==OA_IPC_OK && required>1);
#ifdef __APPLE__
    CHECK(required==sizeof expected && strcmp(buffer,expected)==0);
#endif
#ifdef _WIN32
    windows_process_environment_test();
    CHECK(strstr(buffer,"openabstractions-user-S-1-")!=NULL);
#endif
}
int main(void) {
    bootstrap_test();
    oa_ipc_connection* c = NULL;
    size_t moved = 42;
    unsigned char data[] = {0, 10, 255, 65, 0, 13, 10};
    unsigned char result[sizeof data];
    size_t total = 0;
    CHECK(oa_ipc_version() == 1);
    CHECK(oa_ipc_open(NULL, 0, 10, &c) == OA_IPC_INVALID_ARGUMENT && c == NULL);
    CHECK(oa_ipc_open("bad", 3, 10, NULL) == OA_IPC_INVALID_ARGUMENT);
    CHECK(oa_ipc_open("a\0b", 3, 10, &c) == OA_IPC_INVALID_ARGUMENT && c == NULL);
    CHECK(oa_ipc_write(NULL, data, sizeof data, &moved) == OA_IPC_INVALID_ARGUMENT && moved == 0);
    CHECK(oa_ipc_read(NULL, result, sizeof result, &moved) == OA_IPC_INVALID_ARGUMENT && moved == 0);
    CHECK(oa_ipc_open("missing-local-endpoint", sizeof "missing-local-endpoint" - 1, 10, &c) == OA_IPC_IO_ERROR && c == NULL);
    oa_ipc_close(NULL);
    {
        const char* endpoint = fixture_start();
        CHECK(oa_ipc_open(endpoint, strlen(endpoint), 0, &c) == OA_IPC_TIMEOUT && c == NULL);
        CHECK(oa_ipc_open(endpoint, strlen(endpoint), 2000, &c) == OA_IPC_OK && c != NULL);
    }
    CHECK(oa_ipc_write(c, data, sizeof data, NULL) == OA_IPC_INVALID_ARGUMENT);
    CHECK(oa_ipc_read(c, result, sizeof result, NULL) == OA_IPC_INVALID_ARGUMENT);
    CHECK(oa_ipc_write(c, NULL, 1, &moved) == OA_IPC_INVALID_ARGUMENT && moved == 0);
    CHECK(oa_ipc_read(c, NULL, 1, &moved) == OA_IPC_INVALID_ARGUMENT && moved == 0);
    CHECK(oa_ipc_read(c, result, 0, &moved) == OA_IPC_INVALID_ARGUMENT && moved == 0);
    CHECK(oa_ipc_write(c, NULL, 0, &moved) == OA_IPC_OK && moved == 0);
    CHECK(oa_ipc_write(c, data, sizeof data, &moved) == OA_IPC_OK && moved == sizeof data);
    while (total < sizeof result) {
        oa_ipc_status status = oa_ipc_read(c, result + total, 1, &moved);
        CHECK(status == OA_IPC_OK && moved == 1);
        if (status != OA_IPC_OK) break;
        total += moved;
    }
    CHECK(total == sizeof data && memcmp(data, result, sizeof data) == 0);
    CHECK(oa_ipc_write(c, "!", 1, &moved) == OA_IPC_OK);
    CHECK(oa_ipc_read(c, result, sizeof result, &moved) == OA_IPC_DISCONNECTED && moved == 0);
    oa_ipc_close(c);
    CHECK(fixture_finish());
    return failures ? 1 : 0;
}
