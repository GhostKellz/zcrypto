// Execute a wasm32-wasi module under Node's WASI and report what happened.
//
// This exists because `zig build -Dtarget=wasm32-wasi` cannot run what it
// builds: the build runner can only spawn binaries the host executes natively,
// so every wasm test root compiled and then failed with "unable to spawn
// foreign binary". Nothing in the project had ever executed a wasm module.
//
// The contract is that this process's exit status is the result. The harnesses
// this replaces printed `WASI_EXIT=<n>` and exited 0 regardless, so a module
// that trapped, aborted, or failed to link produced a green run. Every path
// below therefore ends in an explicit exit code, and `--expect` makes the
// intended outcome part of the invocation rather than something a reader infers
// from which script was called.
//
// Runtime: Node's `node:wasi`, WASI preview1. That is the only environment this
// script claims. A module that runs here is not thereby shown to run in a
// browser, which provides no WASI at all.

import { readFile } from "node:fs/promises";
import { WASI } from "node:wasi";

// The observable outcomes, kept as a closed set so `--expect` cannot name one
// that can never be produced.
const OUTCOMES = Object.freeze({
  // Ran to completion and exited 0.
  OK: "ok",
  // Ran and exited non-zero. A Zig test binary reporting failures lands here,
  // as does a caught error propagated out of main.
  NONZERO: "nonzero",
  // Trapped: unreachable, an out-of-bounds access, a failed `@panic` on a
  // target with no abort path. Distinct from `nonzero` because a trap means
  // the module lost control, not that it reported a result.
  TRAP: "trap",
  // Refused to instantiate because the host did not supply an import the
  // module requires. This is a property of the host/module pair, not of
  // anything the module's code does, so it is reported separately.
  LINK_ERROR: "link-error",
});

function usage(message) {
  process.stderr.write(
    `${message}\n\n` +
      "usage: node dev/wasm/run.mjs --module=<file.wasm> --expect=<outcome>\n" +
      "                            [--entropy=<ok|missing|failing>] [--arg=<v>]...\n\n" +
      `  --expect   one of: ${Object.values(OUTCOMES).join(", ")}\n` +
      "  --entropy  how to supply wasi_snapshot_preview1.random_get:\n" +
      "               ok       the host CSPRNG (default)\n" +
      "               missing  omit the import entirely\n" +
      "               failing  present, but always returns EIO\n",
  );
  process.exit(2);
}

function parseArgs(argv) {
  const opts = { module: null, expect: null, entropy: "ok", args: [] };
  for (const raw of argv) {
    const eq = raw.indexOf("=");
    if (!raw.startsWith("--") || eq === -1) usage(`unrecognised argument: ${raw}`);
    const key = raw.slice(2, eq);
    const value = raw.slice(eq + 1);
    switch (key) {
      case "module":
        opts.module = value;
        break;
      case "expect":
        opts.expect = value;
        break;
      case "entropy":
        opts.entropy = value;
        break;
      case "arg":
        opts.args.push(value);
        break;
      default:
        usage(`unrecognised option: --${key}`);
    }
  }
  if (!opts.module) usage("--module is required");
  if (!opts.expect) usage("--expect is required");
  if (!Object.values(OUTCOMES).includes(opts.expect)) {
    usage(`--expect=${opts.expect} is not an outcome this runner can produce`);
  }
  if (!["ok", "missing", "failing"].includes(opts.entropy)) {
    usage(`--entropy=${opts.entropy} is not a supported entropy mode`);
  }
  return opts;
}

// __WASI_ERRNO_IO. Returned by the `failing` entropy mode so the module sees a
// host whose CSPRNG is present and broken -- the case a fail-closed library has
// to handle, and the one a missing import cannot exercise because it stops the
// module before any code runs.
const ERRNO_IO = 29;

// Build the import object, applying the requested entropy mode.
//
// The namespace is rebuilt as a plain own-property object rather than mutated
// in place. Node's `getImportObject()` namespace carries each syscall as an own
// property *and* on its prototype, so `delete ns.random_get` returns true,
// removes the own property, and leaves the prototype's copy fully visible to
// the WebAssembly import lookup -- which resolves through the prototype chain.
// The module then links successfully and calls a prototype method with no
// receiver, and V8 aborts the whole process with
// "GetAlignedPointerFromInternalField: Internal field out of bounds": a fatal
// error, not a catchable one. The `missing` mode was therefore untestable by
// deletion, and any harness that tried it was measuring a Node crash rather
// than a module's behaviour without entropy.
//
// Spreading into a fresh object drops the prototype, so the remaining entries
// are exactly the own properties and an absent one is genuinely absent.
function buildImports(wasi, mode) {
  const source = wasi.getImportObject().wasi_snapshot_preview1;
  if (!source) throw new Error("WASI import object has no wasi_snapshot_preview1 namespace");

  // Asserted rather than assumed. If a future Node stopped providing
  // `random_get`, removing it would be a no-op and the `missing` mode would
  // test nothing while still reporting a pass.
  if (typeof source.random_get !== "function") {
    throw new Error(`entropy mode '${mode}' needs a baseline random_get to alter; none present`);
  }

  const ns = { ...source };
  if (mode === "missing") {
    delete ns.random_get;
    if ("random_get" in ns) throw new Error("random_get survived removal; the namespace is not a plain object");
  } else if (mode === "failing") {
    ns.random_get = () => ERRNO_IO;
  }
  return { wasi_snapshot_preview1: ns };
}

function classify(error) {
  // Node reports a missing import as LinkError, and a trap as RuntimeError.
  // Both are subclasses of Error with stable `name`s, which is more robust
  // than matching message text across Node versions.
  if (error instanceof WebAssembly.LinkError) return OUTCOMES.LINK_ERROR;
  if (error instanceof WebAssembly.RuntimeError) return OUTCOMES.TRAP;
  return null;
}

async function observe(opts) {
  const bytes = await readFile(opts.module);
  const wasi = new WASI({
    version: "preview1",
    args: ["zcrypto", ...opts.args],
    env: {},
    // Without this, `proc_exit` terminates *this* process with the module's
    // status and everything below is unreachable -- including the comparison
    // against `--expect`, so an expected-failure run would kill the runner
    // instead of passing.
    returnOnExit: true,
  });

  const imports = buildImports(wasi, opts.entropy);

  let instance;
  try {
    instance = await WebAssembly.instantiate(await WebAssembly.compile(bytes), imports);
  } catch (error) {
    const outcome = classify(error);
    if (outcome === null) throw error;
    return { outcome, detail: `${error.name}: ${error.message}` };
  }

  let code;
  try {
    code = wasi.start(instance);
  } catch (error) {
    const outcome = classify(error);
    if (outcome === null) throw error;
    return { outcome, detail: `${error.name}: ${error.message}` };
  }

  // `wasi.start` resolves to undefined when the module returns from `_start`
  // without calling `proc_exit`, which is a normal exit-0.
  const status = code ?? 0;
  return {
    outcome: status === 0 ? OUTCOMES.OK : OUTCOMES.NONZERO,
    detail: `exit status ${status}`,
  };
}

const opts = parseArgs(process.argv.slice(2));
const observed = await observe(opts);

if (observed.outcome !== opts.expect) {
  process.stderr.write(
    `\nwasm run: expected ${opts.expect}, observed ${observed.outcome}\n` +
      `  module:  ${opts.module}\n` +
      `  args:    ${JSON.stringify(opts.args)}\n` +
      `  entropy: ${opts.entropy}\n` +
      `  detail:  ${observed.detail}\n`,
  );
  process.exit(1);
}

process.stdout.write(`wasm run: ${observed.outcome} as expected (${observed.detail})\n`);
