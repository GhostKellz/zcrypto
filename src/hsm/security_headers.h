// Translation unit for the Apple Secure Enclave backend.
//
// Mirrors `tss2_headers.h` and `pkcs11_headers.h`: one header whose only job is
// to name the system declarations `secure_enclave.zig` needs, so `build.zig` has
// a single file to hand to `translate-c`.
//
// CoreFoundation comes first because every Security.framework call traffics in
// CF types -- CFDictionaryRef for attributes, CFDataRef for key bytes and
// signatures, CFErrorRef for failures -- and the enclave attributes themselves
// are CFStringRef constants.
// Deliberately NOT the `<Security/Security.h>` umbrella. That header drags in
// Authorization and, through it, `<xpc/xpc.h>`, whose `XPC_NONNULL_ARRAY` puts
// a nullability specifier on the non-pointer `uuid_t` -- which translate-c
// rejects outright. The three headers below are the ones this backend uses and
// they carry no such dependency.
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecKey.h>
#include <Security/SecAccessControl.h>
#include <Security/SecItem.h>
