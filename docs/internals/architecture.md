# Architecture

This document describes zcrypto's package structure, build-time feature model,
and the main data flows that matter to downstream consumers.

## High-Level Overview

```mermaid
flowchart TD
    consumer["Zig consumer<br/>app, zquic, library"] --> root["zcrypto root module"]

    root --> stable["Stable core"]
    root --> quic["QUIC helpers"]
    root --> gated["Feature-gated modules"]
    root --> compat["Compatibility aliases"]

    stable --> hash["hash / blake3 / auth"]
    stable --> sym["sym"]
    stable --> asym["asym / kex"]
    stable --> kdf["kdf / rand / util"]
    stable --> misc["batch / merkle / timing / arena"]

    quic --> quic_crypto["quic_crypto"]
    quic --> quic_mod["quic"]

    gated --> tls["tls"]
    gated --> async["async_crypto"]
    gated --> hardware["hardware"]
    gated --> pq["post_quantum"]
    gated --> research["blockchain / vpn / wasm / enterprise / zkp"]
```

## Build Graph

zcrypto uses `build.zig` feature flags to include only the requested modules and
to gate experimental surfaces.

```mermaid
flowchart LR
    build["build.zig"] --> opts["build_options"]
    build --> core["zcrypto_core"]
    build --> root["zcrypto"]

    opts --> root
    core --> root

    build --> tls{"-Dtls"}
    build --> hw{"-Dhardware-accel"}
    build --> async{"-Dasync"}
    build --> pq{"-Dpost-quantum"}
    build --> exp{"-Dexperimental-crypto"}

    tls --> tlsmod["zcrypto_tls"]
    hw --> hwmod["zcrypto_hw"]
    async --> zsync["zsync v0.8.4"]
    zsync --> asyncmod["zcrypto_async"]
    pq --> exp
    exp --> pqmod["zcrypto_pq"]

    tlsmod --> root
    hwmod --> root
    asyncmod --> root
    pqmod --> root
```

## Stable API Flow

Stable core APIs are thin, explicit wrappers around Zig standard-library crypto
or locally verified helpers. Allocator-taking functions return caller-owned
buffers unless a returned type documents `deinit`.

```mermaid
sequenceDiagram
    participant App as Consumer
    participant API as zcrypto stable API
    participant Std as Zig std.crypto
    participant Alloc as Allocator

    App->>API: hash/sign/encrypt/derive/fill
    API->>Std: use audited primitive where available
    API->>Alloc: allocate only when API returns owned slices
    API-->>App: value or caller-owned buffer
    App->>Alloc: free returned buffers
```

## QUIC Crypto Flow

QUIC consumers such as zquic rely on zcrypto for stable primitives and packet
protection helpers.

```mermaid
flowchart TD
    cid["Connection ID / TLS secret"] --> derive["HKDF labels + traffic secrets"]
    derive --> keys["AEAD key / IV / header protection key"]
    packet["QUIC packet"] --> protect["Packet protection"]
    keys --> protect
    protect --> wire["Encrypted packet + protected header"]

    wire --> unprotect["Header unprotect + packet decrypt"]
    keys --> unprotect
    unprotect --> plaintext["Plaintext frame payload"]
```

## Experimental Gate

Experimental crypto is intentionally explicit. The feature flag alone is not
enough for PQ, blockchain, enterprise/formal, or ZKP code.

```mermaid
flowchart TD
    request["Consumer enables optional crypto"] --> feature{"Feature flag enabled?"}
    feature -->|no| empty["Feature namespace disabled"]
    feature -->|yes| experimental{"Experimental family?"}
    experimental -->|no| enabled["Feature module enabled"]
    experimental -->|yes| optin{"-Dexperimental-crypto=true?"}
    optin -->|yes| research["Experimental module enabled"]
    optin -->|no| error["Build fails with explicit opt-in error"]
```

## Async Integration

The async feature integrates with zsync while keeping zquic and other consumers
free to disable it.

```mermaid
sequenceDiagram
    participant App as Consumer
    participant Runtime as zsync Runtime
    participant Async as zcrypto.async_crypto
    participant Core as zcrypto core

    App->>Runtime: Runtime.init(allocator, .{})
    Runtime-->>App: rt.io()
    App->>Async: AsyncCrypto.init(rt.io(), allocator)
    App->>Async: encryptAsync/decryptAsync/hashAsync
    Async->>Core: direct crypto operation
    Core-->>Async: result
    Async-->>App: caller-owned result
```

## Downstream Boundary

zcrypto should remain easy to consume from libraries that already own their
runtime and protocol stack.

```mermaid
flowchart LR
    zcrypto["zcrypto"] --> zquic["zquic"]
    zcrypto --> app["Other Zig apps"]
    zsync["zsync"] -. "only when -Dasync=true" .-> zcrypto

    zquic --> stable["Uses stable hash/kdf/rand/kex/sym/quic helpers"]
    zquic --> pq["Uses PQ only behind its own experimental flags"]
    zquic -. "does not require zcrypto async" .-> noasync[".async = false"]
```
