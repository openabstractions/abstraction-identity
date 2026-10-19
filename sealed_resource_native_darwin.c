//go:build darwin && cgo

#include "sealed_resource_native.h"
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct oa_sealed_resource {
  size_t count;
  SecStaticCodeRef codes[16];
  SecRequirementRef exact[16];
  SecRequirementRef trusted;
  oa_sealed_resource_info info[16];
};
static int string_value(CFTypeRef v, char *out, size_t n) {
  if (!v) { out[0]=0; return 1; }
  return CFGetTypeID(v)==CFStringGetTypeID() && CFStringGetCString(v,out,n,kCFStringEncodingUTF8);
}
static OSStatus exact_requirement(CFDictionaryRef info, SecRequirementRef *out) {
  CFTypeRef h=CFDictionaryGetValue(info,kSecCodeInfoUnique);
  if(!h || CFGetTypeID(h)!=CFDataGetTypeID())return errSecCSUnsigned;
  CFIndex n=CFDataGetLength(h);if(n<1 || n>64)return errSecInternalComponent;
  char text[160]="cdhash H\"";const UInt8 *b=CFDataGetBytePtr(h);
  for(CFIndex i=0;i<n;i++)snprintf(text+9+2*i,3,"%02x",b[i]);
  text[9+2*n]='"';text[10+2*n]=0;
  CFStringRef s=CFStringCreateWithCString(NULL,text,kCFStringEncodingUTF8);
  if(!s)return errSecAllocate;
  OSStatus st=SecRequirementCreateWithString(s,0,out);CFRelease(s);return st;
}
void oa_sealed_resource_free(oa_sealed_resource *s) {
  if(!s)return;
  for(size_t i=0;i<16;i++){if(s->codes[i])CFRelease(s->codes[i]);if(s->exact[i])CFRelease(s->exact[i]);}
  if(s->trusted)CFRelease(s->trusted);free(s);
}
int32_t oa_sealed_resource_create(const char *path,const char *relative,const void *bytes,size_t length,
 const uint32_t *cpus,const uint32_t *subs,const uint64_t *offsets,size_t count,
 oa_sealed_resource **out,char *mainName,size_t mainSize,size_t *nativeIndex) {
  if(!path||!relative||!bytes||!length||count<1||count>16||!out||!mainName||mainSize<2||!nativeIndex)return errSecParam;
  *out=NULL;mainName[0]=0;*nativeIndex=(size_t)-1;
  oa_sealed_resource *s=calloc(1,sizeof(*s));if(!s)return errSecAllocate;
  CFURLRef url=NULL;CFStringRef rel=NULL;CFDataRef data=NULL;SecStaticCodeRef native=NULL;
  OSStatus st=SecRequirementCreateWithString(CFSTR("anchor trusted"),0,&s->trusted);if(st)goto end;
  url=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8*)path,strlen(path),true);
  rel=CFStringCreateWithCString(NULL,relative,kCFStringEncodingUTF8);data=CFDataCreate(NULL,bytes,length);
  if(!url||!rel||!data){st=errSecAllocate;goto end;}
  for(size_t i=0;i<count;i++) {
    CFNumberRef cpu=CFNumberCreate(NULL,kCFNumberSInt32Type,&cpus[i]),sub=CFNumberCreate(NULL,kCFNumberSInt32Type,&subs[i]),offset=CFNumberCreate(NULL,kCFNumberSInt64Type,&offsets[i]);
    if(!cpu||!sub||!offset){if(cpu)CFRelease(cpu);if(sub)CFRelease(sub);if(offset)CFRelease(offset);st=errSecAllocate;goto end;}
    const void *keys[]={kSecCodeAttributeArchitecture,kSecCodeAttributeSubarchitecture,kSecCodeAttributeUniversalFileOffset},*values[]={cpu,sub,offset};
    CFDictionaryRef attrs=CFDictionaryCreate(NULL,keys,values,count>1?3:2,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFRelease(cpu);CFRelease(sub);CFRelease(offset);if(!attrs){st=errSecAllocate;goto end;}
    st=SecStaticCodeCreateWithPathAndAttributes(url,0,attrs,&s->codes[i]);CFRelease(attrs);if(st)goto end;
    /* Each new slice object is checked explicitly. A cached all-architectures
       call cannot replace these checks (1456-B adverse universal fixture). */
    st=SecStaticCodeCheckValidity(s->codes[i],kSecCSStrictValidate|kSecCSNoNetworkAccess,s->trusted);if(st)goto end;
    st=SecCodeValidateFileResource(s->codes[i],rel,data,0);if(st)goto end;
    CFDictionaryRef info=NULL;st=SecCodeCopySigningInformation(s->codes[i],kSecCSSigningInformation,&info);if(st||!info){if(!st)st=errSecInternalComponent;goto end;}
    CFTypeRef plist=CFDictionaryGetValue(info,kSecCodeInfoPList);char main[1024];
    if(!plist || CFGetTypeID(plist)!=CFDictionaryGetTypeID() || !CFEqual(CFDictionaryGetValue(plist,CFSTR("CFBundlePackageType"))?:CFSTR(""),CFSTR("APPL")) || !string_value(CFDictionaryGetValue(plist,CFSTR("CFBundleExecutable")),main,sizeof main) || !main[0] || strlen(main)>=mainSize){st=errSecCSInfoPlistFailed;CFRelease(info);goto end;}
    if(i && strcmp(mainName,main)){st=errSecCSInfoPlistFailed;CFRelease(info);goto end;}strcpy(mainName,main);
    if(!string_value(CFDictionaryGetValue(info,kSecCodeInfoTeamIdentifier),s->info[i].team,sizeof s->info[i].team)){st=errSecInternalComponent;CFRelease(info);goto end;}
    CFTypeRef certs=CFDictionaryGetValue(info,kSecCodeInfoCertificates);
    if(!certs||CFGetTypeID(certs)!=CFArrayGetTypeID()||CFArrayGetCount(certs)<1){st=errSecCSUnsigned;CFRelease(info);goto end;}
    CFStringRef subject=SecCertificateCopySubjectSummary((SecCertificateRef)CFArrayGetValueAtIndex(certs,0));
    CFStringRef issuer=CFArrayGetCount(certs)>1?SecCertificateCopySubjectSummary((SecCertificateRef)CFArrayGetValueAtIndex(certs,1)):NULL;
    int copied=string_value(subject,s->info[i].subject,sizeof s->info[i].subject)&&string_value(issuer,s->info[i].issuer,sizeof s->info[i].issuer);
    if(subject)CFRelease(subject);if(issuer)CFRelease(issuer);
    st=copied?exact_requirement(info,&s->exact[i]):errSecInternalComponent;CFRelease(info);if(st)goto end;s->count++;
  }
  /* Determine which already authenticated slice is native on this host. The
     default object's generation is only a selector, never additional evidence. */
  st=SecStaticCodeCreateWithPath(url,0,&native);if(st)goto end;
  for(size_t i=0;i<count;i++)if(SecStaticCodeCheckValidity(native,kSecCSStrictValidate|kSecCSNoNetworkAccess,s->exact[i])==0){*nativeIndex=i;break;}
  if(*nativeIndex==(size_t)-1){st=errSecCSReqFailed;goto end;}
  *out=s;s=NULL;st=0;
end:
  if(native)CFRelease(native);if(url)CFRelease(url);if(rel)CFRelease(rel);if(data)CFRelease(data);oa_sealed_resource_free(s);return st;
}
int32_t oa_sealed_resource_info_at(oa_sealed_resource *s,size_t i,oa_sealed_resource_info *out){if(!s||i>=s->count||!out)return errSecParam;*out=s->info[i];return 0;}
int32_t oa_sealed_resource_match_code(oa_sealed_resource *s,SecCodeRef code,size_t *index){
  if(!s||!code||!index)return errSecParam;
  OSStatus st=SecCodeCheckValidity(code,kSecCSNoNetworkAccess,s->trusted);if(st)return st;
  for(size_t i=0;i<s->count;i++)if(SecCodeCheckValidity(code,kSecCSNoNetworkAccess,s->exact[i])==0){*index=i;return 0;}
  return errSecCSReqFailed;
}
