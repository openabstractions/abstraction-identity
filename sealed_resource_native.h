#ifndef OA_SEALED_RESOURCE_NATIVE_H
#define OA_SEALED_RESOURCE_NATIVE_H
#include <stddef.h>
#include <stdint.h>
#include "xpc_native.h"
typedef struct oa_sealed_resource oa_sealed_resource;
typedef struct oa_sealed_resource_info {
  char subject[1024], issuer[1024], team[256];
} oa_sealed_resource_info;
int32_t oa_sealed_resource_create(const char *, const char *, const void *, size_t,
  const uint32_t *, const uint32_t *, const uint64_t *, size_t,
  oa_sealed_resource **, char *, size_t, size_t *);
int32_t oa_sealed_resource_info_at(oa_sealed_resource *, size_t, oa_sealed_resource_info *);
void oa_sealed_resource_free(oa_sealed_resource *);
/* Borrowed while the process owner lives. No caller supplies a code pointer. */
void *oa_xpc_process_sealed_resource_code(oa_xpc_process *);
#ifdef __APPLE__
#include <Security/Security.h>
int32_t oa_sealed_resource_match_code(oa_sealed_resource *, SecCodeRef, size_t *);
#endif
#endif
