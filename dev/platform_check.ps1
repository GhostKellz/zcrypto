#Requires -Version 5.1
#
# Native platform evidence for one Windows host.
#
# This is the Windows half of `dev/platform_check.sh` and emits the same record
# format, so the two can be concatenated into one matrix without a translation
# step. It is a separate file rather than a shim over the shell script because
# the only `bash` on the Windows lab host is the WSL launcher: running the shell
# script there would certify a Linux guest and label the result Windows.
#
# Run this ON the machine being certified, not on the dev host with a
# `-Dtarget=` flag. A cross-compiled binary proves the code compiles for a
# platform; it proves nothing about running there, which is where the platform
# branches in this library actually differ. The script refuses to produce a
# record if the build is not native -- see `Test-Native` below.
#
# Output is a machine-readable evidence record on stdout. Per-stage logs are
# written under a run directory and are retained on failure.
#
# Environment:
#   ZIG                        Compiler to use (default: first `zig` on PATH).
#   ZCRYPTO_PLATFORM_KEEP=1    Keep this run's scratch directory and logs.

Set-StrictMode -Version 2.0

# Native `zig` writes progress to stderr. Under the default 'Stop' preference a
# caller that set it would turn that into a terminating error and lose the run,
# so this is pinned rather than inherited.
$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $repoRoot

$zigBin = if ($env:ZIG) { $env:ZIG } else { 'zig' }
$zigCmd = Get-Command $zigBin -ErrorAction SilentlyContinue
if (-not $zigCmd) {
    [Console]::Error.WriteLine("platform_check: no compiler: $zigBin")
    exit 127
}
$zigExe = $zigCmd.Source

$scratch = Join-Path $repoRoot '.scratch'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$suffix = [System.IO.Path]::GetRandomFileName().Replace('.', '').Substring(0, 6)
$runDir = Join-Path $scratch "platform-$stamp-$suffix"
$logDir = Join-Path $runDir 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

if (-not $env:ZIG_GLOBAL_CACHE_DIR) {
    $env:ZIG_GLOBAL_CACHE_DIR = Join-Path $scratch 'zig-global-cache'
}
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $runDir 'zig-local-cache'
New-Item -ItemType Directory -Force -Path $env:ZIG_GLOBAL_CACHE_DIR | Out-Null

$script:failCount = 0
$script:passCount = 0
$script:runnersPending = 0
$script:stageIndex = 0

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
# Everything here is read out of the machine and the toolchain rather than
# passed in, so a record cannot be mislabelled by the caller that requested it.

$zigVersion = (& $zigExe version 2>$null | Select-Object -First 1)

# `zig env` reports the *detected native* target, including the OS version range
# it probed for. That is the identity that matters for this record: two hosts
# reporting the same build number can still resolve different targets.
$zigTarget = ''
foreach ($line in (& $zigExe env 2>$null)) {
    if ($line -match '^\s*\.target = "(.*)",$') { $zigTarget = $Matches[1] }
}

# PROCESSOR_ARCHITECTURE reports the architecture of the *process*, so a 32-bit
# PowerShell on a 64-bit host reports x86. PROCESSOR_ARCHITEW6432 is set only in
# that case and carries the real one.
$hostArchRaw = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $hostArchRaw = $env:PROCESSOR_ARCHITEW6432 }

function Write-Identity {
    'ZCRYPTO_PLATFORM_EVIDENCE|v1'
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        "host.uname|Windows $($os.Version) build $($os.BuildNumber) $hostArchRaw"
    } else {
        "host.uname|Windows $([System.Environment]::OSVersion.Version) $hostArchRaw"
    }
    "host.name|$env:COMPUTERNAME"
    "host.utc|$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    "zig.exe|$zigExe"
    "zig.version|$zigVersion"
    "zig.native_target|$zigTarget"
    # The tree under test, not the tree the driver believes it sent. A dirty
    # worktree is normal here and is recorded rather than rejected: this gate
    # runs against work in progress far more often than against a tag.
    $git = Get-Command git -ErrorAction SilentlyContinue
    $head = $null
    if ($git) { $head = (& git rev-parse HEAD 2>$null | Select-Object -First 1) }
    if ($head) {
        "repo.commit|$head"
        $porcelain = (& git status --porcelain 2>$null)
        if ($porcelain) { 'repo.worktree|dirty' } else { 'repo.worktree|clean' }
    } else {
        # The driver ships a source snapshot, not a repository, so this is the
        # normal case on a remote host. The driver stamps the origin instead.
        'repo.commit|unavailable-no-git-dir'
        'repo.worktree|unknown'
    }
    $originFile = Join-Path $repoRoot '.zcrypto-origin'
    if (Test-Path -LiteralPath $originFile) {
        "repo.origin|$((Get-Content -LiteralPath $originFile -Raw).Trim())"
    }
}

# ---------------------------------------------------------------------------
# Native check
# ---------------------------------------------------------------------------
# The item this script exists to satisfy says a cross-compiled binary is not a
# native pass, so that has to be enforced rather than trusted. Two independent
# checks, because either alone is weak: the OS/arch comparison catches a record
# produced on the wrong machine, and the `-Dtarget` scan in `Invoke-Stage`
# catches a stage list edited to cross-compile on the right one.
#
# The verdict travels in `$script:nativeOk` rather than as a return value. A
# PowerShell function returns *everything* written to its output stream, so one
# that emits a record line and then returns a boolean actually returns a
# two-element array -- which is truthy whatever the check decided, and which
# swallows the record line instead of printing it. Keeping the two apart makes
# that failure mode unavailable rather than merely avoided.
$script:nativeOk = $false

function Write-NativeCheck {
    switch ($hostArchRaw) {
        'AMD64' { $wantArch = 'x86_64' }
        'ARM64' { $wantArch = 'aarch64' }
        'x86'   { $wantArch = 'x86' }
        default { $wantArch = $hostArchRaw.ToLower() }
    }
    $want = "$wantArch-windows"
    if (-not $zigTarget.StartsWith($want)) {
        "native.check|FAIL: zig reports '$zigTarget', host is '$want'"
        $script:nativeOk = $false
        return
    }
    "native.check|ok ($want)"
    $script:nativeOk = $true
}

# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------
# Each stage records the exact argv, the exit status, and -- for test stages --
# the compiler's own count of tests run. The count is load-bearing: a build
# whose test step matched nothing still exits 0, and without the count a record
# saying `exit=0` could not be told apart from one that verified nothing.

function Invoke-Stage {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string[]] $StageArgs
    )

    $script:stageIndex++
    $argv = "$zigExe $($StageArgs -join ' ')"

    # Refuse to certify a stage that cross-compiles. This is checked per stage
    # rather than once, so adding a `-Dtarget` later cannot slip past.
    foreach ($a in $StageArgs) {
        if ($a -like '-Dtarget=*') {
            "STAGE|$Name|$argv|refused|cross-compile: $a"
            $script:failCount++
            return
        }
    }

    $log = Join-Path $logDir ('{0:d2}-{1}.log' -f $script:stageIndex, $Name)
    & $zigExe @StageArgs 2>&1 |
        ForEach-Object { $_.ToString() } |
        Out-File -LiteralPath $log -Encoding utf8
    $status = $LASTEXITCODE

    $lines = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue)

    # Keep the skip parenthetical the build runner appends. A skipped test and a
    # passing one are both "not a failure" to the exit status, and the whole
    # point of this record is that the two are told apart.
    $counts = '-'
    $hit = $lines | Select-String -Pattern '; (\d+/\d+ tests passed.*)$' | Select-Object -Last 1
    if ($hit) {
        $counts = $hit.Matches[0].Groups[1].Value
    } else {
        $hit = $lines | Select-String -Pattern 'All (\d+) tests passed' | Select-Object -Last 1
        if ($hit) { $counts = "$($hit.Matches[0].Groups[1].Value) tests passed" }
    }

    if ($status -eq 0) { $script:passCount++ } else { $script:failCount++ }

    "STAGE|$Name|$argv|exit=$status|$counts"

    # Name the skips. A total of "6 skipped" tells a reader that something was
    # not verified but not what, which is the difference between a known gap and
    # an unknown one. The build runner prints the owning test binary per step.
    #
    # These lines only appear on a step that actually ran, so the record would
    # lose them to a warm cache -- which is why ZIG_LOCAL_CACHE_DIR is per-run
    # above. Every stage here executes from cold.
    foreach ($s in ($lines | Select-String -Pattern 'run test ([A-Za-z0-9._-]+) \d+ pass, (\d+) skip')) {
        "SKIP|$Name|$($s.Matches[0].Groups[1].Value) $($s.Matches[0].Groups[2].Value) skipped"
    }

    if ($status -ne 0) {
        # A failure that reports only its exit status is not evidence anyone can
        # act on from another machine, so the tail travels with the record.
        foreach ($l in ($lines | Select-Object -Last 25)) { "LOG|$Name|$l" }
    }
}

# A runner that is absent must appear in the record as an explicit skip with a
# reason. Omitting it silently is what turns "we did not test this" into "this
# passed everywhere" by the time the matrix is read.
function Write-RunnerProbe {
    param([string] $Name, [string] $Command, [string] $Why)
    $c = Get-Command $Command -ErrorAction SilentlyContinue
    if ($c) {
        "RUNNER|$Name|available|$($c.Source)"
    } else {
        "RUNNER|$Name|pending|$Why"
        $script:runnersPending++
    }
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

try {
    Write-Identity

    Write-NativeCheck
    if (-not $script:nativeOk) {
        'RESULT|refused pass=0 fail=1 runners_pending=0'
        $script:failCount = 1
        exit 2
    }

    # Optional external runners. Each one backs a real stage of
    # `release_check.sh` that cannot run without a host service, so the record
    # says which were present rather than leaving the reader to assume this host
    # could have run everything. Nothing is probed speculatively: a runner listed
    # here that gates no existing stage would read as "this host skipped a check"
    # when no such check exists.
    Write-RunnerProbe 'swtpm' 'swtpm' `
        "no software TPM; release_check.sh stage 'tpm-simulator' (dev/tpm_swtpm.sh) cannot run here"
    Write-RunnerProbe 'softhsm' 'softhsm2-util' `
        "no SoftHSM token; release_check.sh stage 'pkcs11-softoken' (dev/pkcs11_softoken.sh) cannot run here"
    Write-RunnerProbe 'system-cc' 'cl' `
        "no MSVC cl.exe; release_check.sh stage 'ffi-consumer-system-cc' cannot run here"

    Invoke-Stage 'build'                       @('build')
    Invoke-Stage 'test-debug'                  @('build', 'test', '-Doptimize=Debug', '--summary', 'all')
    Invoke-Stage 'test-releasesafe'            @('build', 'test', '-Doptimize=ReleaseSafe', '--summary', 'all')
    Invoke-Stage 'test-releasefast'            @('build', 'test', '-Doptimize=ReleaseFast', '--summary', 'all')
    Invoke-Stage 'hardware-parity-debug'       @('build', 'hardware-parity', '-Doptimize=Debug')
    Invoke-Stage 'hardware-parity-releasefast' @('build', 'hardware-parity', '-Doptimize=ReleaseFast')
    Invoke-Stage 'kat'                         @('build', 'kat')
    Invoke-Stage 'ffi-consumer'                @('build', 'ffi-consumer')
    Invoke-Stage 'run-core'                    @('build', 'run-core')

    # `runners_pending` counts absent host services, not skipped tests. Those are
    # the `SKIP|` lines above and are a different thing entirely: a pending runner
    # means a stage could not be attempted on this host, a skipped test means a
    # stage ran and declined a case. Calling both "skip" in one record invites the
    # reader to add them up.
    "RESULT|pass=$($script:passCount) fail=$($script:failCount) runners_pending=$($script:runnersPending)"
} finally {
    if ($env:ZCRYPTO_PLATFORM_KEEP -and $env:ZCRYPTO_PLATFORM_KEEP -ne '0') {
        "LOGS|$runDir"
    } elseif ($script:failCount -ne 0) {
        "LOGS|$runDir"
    } else {
        Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($script:failCount -eq 0) { exit 0 } else { exit 1 }
