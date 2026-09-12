/* Translation unit for the TPM2-TSS ESAPI surface used by src/hsm/tpm2.zig.
 *
 * Zig 0.17 removed @cImport, so the bindings are produced by a
 * `b.addTranslateC` step over this file. Keeping the include set in one place
 * means the module boundary is explicit: anything tpm2.zig reaches for must
 * be listed here.
 *
 *   tss2_esys.h    - the ESAPI command layer (Esys_*)
 *   tss2_tctildr.h - the TCTI loader, so the transport is a runtime string
 *   tss2_rc.h      - Tss2_RC_Decode, for human-readable failures
 *   tss2_mu.h      - canonical marshalling, so a sealed blob is persisted in
 *                    the TPM wire encoding rather than as a raw copy of a C
 *                    struct whose layout is a property of this compiler
 */
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>
