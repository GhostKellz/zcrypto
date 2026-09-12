/* Translation unit for the PKCS#11 (Cryptoki) surface used by
 * src/hsm/pkcs11.zig.
 *
 * Zig 0.17 removed @cImport, so the bindings are produced by a
 * `b.addTranslateC` step over this file.
 *
 * Nothing here is linked. A PKCS#11 provider is loaded at runtime with dlopen
 * from a path the caller supplies, so this header contributes types and
 * constants only. It is translated rather than transcribed into Zig because
 * `CK_ULONG` is `unsigned long`: 8 bytes on 64-bit Unix and 4 bytes on Windows.
 * That width is load-bearing in every struct below, and a hand-written copy
 * that got one field wrong would misparse a token's answers rather than fail
 * to compile.
 *
 * p11-kit's copy is used because it is the one packaged on this host. It
 * defaults to `CRYPTOKI_COMPAT`, which is the ABI every shipped module
 * implements; the alternative `CRYPTOKI_GNU` spelling is a different ABI and
 * must not be selected here.
 */
#include <p11-kit/pkcs11.h>
