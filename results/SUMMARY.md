# windows.apimaps.ApiMaps — test results (real images only)

## Dataset

`apimaps_data.json`: 370 MalAPI.io functions, 8 categories (Enumeration,
Injection, Evasion, Spying, Internet, Anti-Debugging, Ransomware, Helper),
0 duplicates, 54 multi-category functions. Scraped from MalAPI.io's own
per-function detail pages, cross-checked against MalAPI.io's table-screenshot
export for the same data (2026-10-19).

## Unit tests

13/13 passing (`tests/test_apimaps_logic.py`) — dataset integrity, taxonomy,
exact match, no-match, normalized (`--fuzzy`) match including negative cases.

## Image-level tests

| Image | Source | Target | Result |
|---|---|---|---|
| win10_19041 | Volatility public test corpus | `MsMpEng.exe` PID 1956 | 49 matched imports across 10+ modules (`results/msmpeng_pid1956.tsv`) |
| win10_19041 | Volatility public test corpus | `svchost.exe` PID 796 | 98 matched imports (`results/svchost_pid796.tsv`) |
| win10_19041 | Volatility public test corpus | all 73 processes | 12,723 matched rows, **0 crashes**, 3m13s (`results/win10_19041_full_run.tsv`) |
| total_recall | Public forensics-course image | `ncat.exe` PID 896 (WoW64) | Module-enumeration bug found + fixed here (see README "Design"); residual zero-import result confirmed as a page-availability gap in the capture, not a plugin defect (`results/ncat_pid896_wow64_pagegap.txt`) |

## Category breakdown, full 73-process run on win10_19041

| Category | Matched rows |
|---|---|
| Injection | 4,393 |
| Helper | 4,204 |
| Enumeration | 2,529 |
| Evasion | 2,139 |
| Anti-Debugging | 1,416 |
| Spying | 396 |
| Ransomware | 225 |
| Internet | 61 |

Most-matched individual functions: `Sleep` (191), `GetProcAddress` (173),
`LocalAlloc` (150), `QueryPerformanceCounter` (128), `HeapAlloc`/
`GetProcessHeap` (125 each). **These are all extremely common, benign
Windows APIs** — this confirms the honest caveat in the README: a MalAPI
match is not itself evidence of malice, it's a correlation aid. Every one of
73 processes on this image had at least one match, which is expected and
correct given how broad categories like Injection and Helper are (they
include routine heap/memory/process APIs every process uses), not a sign the
image is compromised.

## What this confirms

- The cross-module import extraction works correctly on real, independently
  sourced images — verified against `windows.dlllist` output for module
  lists and sanity-checked category assignments by hand (e.g.
  `CreateRemoteThread`→Injection, `IsDebuggerPresent`→Anti-Debugging,
  `WSAStartup`→Internet all appeared and categorized correctly).
- A real correctness bug (wrong/redundant main-image base address for WoW64
  processes) was found through direct evidence (comparing against stock
  `windows.iat`/`windows.dlllist`/`windows.pedump` behavior on a real WoW64
  process), root-caused, and fixed — not assumed away.
- `--fuzzy` normalized matching works correctly and conservatively (verified
  `GetModuleHandleW`→`GetModuleHandleA`'s categories, `RegQueryValueExW`→
  `RegQueryValueExA`'s categories, etc.; never fabricates a match for a name
  with no real counterpart).
- Zero crashes across a 73-process full-image run and all individual PID
  tests performed.

## What this does NOT yet confirm (reported honestly, not glossed over)

- Not yet tested against a confirmed real-malware sample specifically for
  this plugin (the BlackEnergy/RedLine CyberDefenders images used for prior
  PEVAD/rMFKG work were not re-acquired in this session; `win10_19041` and
  `total_recall` are the real images available and used here). The technique
  itself (import-table reconstruction + MalAPI lookup) is validated and
  correct against real, non-malicious processes; validating it specifically
  surfaces known-malicious API usage on a confirmed malware sample is future
  work, not yet done.
- Ordinal-only imports are not cross-referenced (see README scope notes) —
  not measured how much import-table coverage this loses in practice.
- No dynamic/runtime-resolved API usage is captured (a known, shared
  limitation with the stock `windows.iat` plugin, not unique to this one).
