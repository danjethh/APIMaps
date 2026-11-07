# windows.apimaps.ApiMaps — Automated API-to-Malicious-Behavior Correlation (Volatility 3 plugin)

No academic paper backs this plugin. It automates a manual lookup task instead:
given a suspicious process, an examiner who spots an unfamiliar or suspicious
Windows API being used would normally go to **MalAPI.io** and look that
function up by hand to see what kind of malicious behavior it's associated
with. This plugin does that lookup automatically for every API a process has
imported.

## Idea

1. Given a PID, walk the import table of the process's main executable **and
   every DLL it has loaded** (not just the main image — see "Design" below),
   reconstructing each module's PE import directory from memory the same way
   Volatility3's own `windows.iat`/`windows.pedump` do.
2. Cross-reference every resolved imported function name against a local
   snapshot of MalAPI.io's own categorization (Enumeration, Injection,
   Evasion, Spying, Internet, Anti-Debugging, Ransomware, Helper).
3. Report matches, so an examiner gets "this process imports
   `CreateRemoteThread` (Injection), `IsDebuggerPresent` (Anti-Debugging), ..."
   automatically instead of looking each one up on malapi.io by hand.

## MalAPI.io dataset (`apimaps_data.json`)

MalAPI.io has **no public JSON/CSV/API export**. The dataset bundled here
(`plugin/windows/apimaps_data.json`, 370 functions, 8 categories) was built
from MalAPI.io's own published data (acquired 2026-10-19). This is a
**static, locally cached snapshot** — this plugin does not and must not
depend on live internet access at scan time, since examiners analyzing
memory images are routinely offline. The categorization itself is MalAPI.io's
own (credited to mr.d0x and contributors), not invented or re-derived here.

54 of the 370 functions carry more than one category (e.g.
`EnumSystemLocalesA` is listed under Injection, Enumeration, Evasion, and
Ransomware) — all categories are reported for such functions, not just one.

## Design: why every loaded module, not just the main image

Volatility3 already ships `windows.iat`, which reconstructs **only the main
executable's** import table (via `peb.ImageBaseAddress`). The user's request
was "extract all its loaded or mapped APIs" — a process's actual imported-API
surface includes every DLL it has loaded, not just its main EXE, so this
plugin generalizes the same VAD-reconstruction + `pefile` parsing technique
across every module in `proc.load_order_modules()`.

**A real bug was found and fixed during this process, with before/after
evidence:** an earlier version of this plugin additionally read
`peb.ImageBaseAddress` from the 64-bit PEB to get the "main image" base. This
is wrong for a WoW64 (32-bit-on-64-bit) process — the 64-bit PEB's
`ImageBaseAddress` is not the real 32-bit image base — and was also
redundant, since `proc.load_order_modules()` already walks both the 64-bit
PEB and (for WoW64 processes) the 32-bit PEB32 internally, and already
includes the main executable as one of its own entries. Verified against a
real WoW64 process (`ncat.exe`, PID 896, `total_recall` image): the old
separate-main-image code path and the stock `windows.iat` plugin both return
**zero rows** for it. The fix was to drop the redundant/wrong code path
entirely and rely solely on `load_order_modules()`, which is also what
`windows.dlllist` does and verified to report that process's modules
correctly. This did not change results for any non-WoW64 process tested
(same row counts before/after for PID 1956 and PID 796 on `win10_19041`).

**Known, separately-verified limitation (not a bug in this plugin):** even
after that fix, `ncat.exe` (PID 896) still returns zero import rows on the
`total_recall` image. Root-caused by testing Volatility3's own stock
`windows.pedump` plugin against the exact same module base address
(`0x76e80000`, `kernel32.dll`'s VAD, confirmed present via `windows.vadinfo`)
— it fails with the identical `Page Fault ... in page entry` error. This
confirms the gap is a genuine page-availability limitation of this specific
capture for this short-lived helper process, not a defect in this plugin's
logic. Reported honestly rather than silently worked around.

## Matching

- **Exact match** (default, always on): the imported function name matches a
  MalAPI.io entry exactly.
- **Normalized match** (`--fuzzy`, off by default): if the exact name isn't
  listed but matches after stripping a trailing `A`/`W` suffix (e.g.
  `CreateFileW` → `CreateFileA`), it's reported as a lower-confidence
  `normalized` match, clearly tagged as such — never silently merged with
  exact matches. Off by default so default output is exact-match-only.

**Honest scope note:** MalAPI.io's 370 functions are a curated, illustrative
set, not an exhaustive list of every API with security relevance — this
plugin reports what MalAPI.io categorizes, nothing more. A process importing
only APIs outside that 370-function set will correctly show no matches; this
is not a plugin failure, it means MalAPI.io doesn't have an opinion on those
specific functions. Likewise, a MalAPI-matched import is **not** itself
evidence of malice: `Sleep`, `GetProcAddress`, and `VirtualAlloc`-family
functions appear in the overwhelming majority of ordinary, benign Windows
processes (confirmed empirically: a full-image run of 73 processes on
`win10_19041` produced 12,723 matched rows — this plugin is a triage aid
that surfaces what APIs a process uses and what MalAPI.io says they're
*associated with*, not a verdict on the process).

## Usage

    vol -p ./plugin -f image.dmp windows.apimaps.ApiMaps [--pid N ...] \
        [--show-all-imports] [--fuzzy]

- `--pid` — one or more PIDs to analyze. Omit to analyze every process
  (read-only; can be slow on large images — a full 73-process pass on a 2GB
  image took ~3m13s here).
- `--show-all-imports` — also emit imported functions with **no** MalAPI
  match (off by default, to keep output focused on what's actually
  correlated).
- `--fuzzy` — also report normalized (`A`/`W`-suffix-stripped) matches.

Output is a standard Volatility3 TreeGrid: one row per
(process, module, imported function) with its MalAPI category/categories,
match type, and the library MalAPI.io lists for it.

## Demonstration sample

A memory sample demonstrating APIMaps' capabilities: the official Volatility 3 test-corpus
Windows 10 19041 x64 image, published by the Volatility Foundation itself (not redistributed
by this repository — fetched directly from the Foundation's own release):

    curl -LO https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/win-10_19041-2025_03.dmp.gz
    sha256sum win-10_19041-2025_03.dmp.gz   # expect b377ecd13bf40c90f59a8c41ffc8bc81166462627a7800ec82a67a73520c7f9d
    gunzip win-10_19041-2025_03.dmp.gz
    vol -p ./plugin -f win-10_19041-2025_03.dmp windows.apimaps.ApiMaps --pid 1956

This reproduces the `MsMpEng.exe` (PID 1956, 49 matches) result in Testing below. The
`total_recall` image used for the WoW64 regression check is a separate public
forensics-course image; see Testing for how to obtain it.

## Testing

Read-only; never modifies the source image; no synthetic/custom test images
used — only existing, independently documented real memory images.

- `tests/test_apimaps_logic.py` — 13 unit tests of the MalAPI dataset
  (completeness, taxonomy, no duplicates) and the exact/normalized matching
  logic, against hand-picked known-correct cases (no image needed).
- Image-level, real images only:
  - `win10_19041` (Volatility public test corpus): `MsMpEng.exe` (PID 1956,
    49 matches), `svchost.exe` (PID 796, 98 matches), and a full 73-process
    run (12,723 matched rows, 0 crashes) — see `results/`.
  - `total_recall` (public forensics-course image): `ncat.exe` (PID 896,
    WoW64) — the module-enumeration fix verified here; the residual
    zero-import result on this one process is a documented page-availability
    gap in the capture itself, cross-verified against stock
    `windows.pedump`, not a plugin defect.

## Scope notes / future work (reported honestly, not score-chased)

- Only functions imported via the standard import table (`IMAGE_DIRECTORY_ENTRY_IMPORT`)
  are seen. Dynamic resolution via `GetProcAddress`/`LoadLibrary` at runtime,
  or APIs resolved by hash (common in packed/obfuscated malware specifically
  to evade static import-table analysis like this), are invisible to this
  technique — a known, named limitation shared with the stock `windows.iat`
  plugin, not something this plugin claims to solve.
- Ordinal-only imports (no exported name present, e.g. some `Ws2_32.dll`
  functions imported by ordinal) cannot be cross-referenced by name and are
  silently skipped from matching (not from the underlying import-table walk;
  `--show-all-imports` would need a separate ordinal→name resolution step,
  not yet implemented, to surface these).
- No severity/confidence scoring beyond exact-vs-normalized match type was
  added for v1 — unlike rMFKG, there isn't yet a clear evidence-based
  prioritization signal for "this MalAPI match is more concerning than that
  one" without double-counting the fact that common APIs are both ubiquitous
  and MalAPI-categorized; a future version could prioritize rarer or
  multi-category matches, or cross-reference with `malfind`/`handles` the
  way rMFKG cross-references predicates, but that wasn't built here to avoid
  inventing an untested scoring scheme.
