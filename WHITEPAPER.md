# APIMaps: Automated API-to-Malicious-Behavior Correlation for Volatility 3

**A Volatility 3 plugin submitted to the Volatility Foundation 14th Annual Plugin Contest**

> **A note on scope, stated up front:** unlike this submission's companion plugins (PEVAD, rMFKG), APIMaps does not implement or extend a peer-reviewed detection technique. It automates an existing, publicly documented manual workflow. This white paper follows the same structure as the others in this submission, but Section 4 states that plainly rather than implying a research contribution that is not there.

---

## 1. Current Industry Practice

When an examiner identifies a suspicious or malicious process in a memory image, a common next step is to inspect which Windows API functions that process has imported, since the set of APIs a process can call is a strong signal of its capability (process injection, keylogging, network exfiltration, anti-debugging, and so on). [MalAPI.io](https://malapi.io) is a public, community-maintained website that categorizes several hundred Windows API functions by the kind of malicious activity each is commonly associated with (Enumeration, Injection, Evasion, Spying, Internet, Anti-Debugging, Ransomware, Helper). Examiners currently use it by looking up each unfamiliar imported function one at a time on the live site.

## 2. The Problem

This manual workflow has two compounding limitations. First, it does not scale: a single process can import hundreds of functions across dozens of DLLs, and each must be looked up individually. Second, the import-extraction step itself is incomplete in existing tooling — Volatility 3's own stock `windows.iat` plugin reconstructs the import table of only a process's **main executable**, not the DLLs it has loaded, so even before an examiner reaches MalAPI.io, the set of functions available to look up is already an undercount of the process's real imported-API surface.

## 3. The Proposed Solution

APIMaps (`windows.apimaps.ApiMaps`) automates the entire pipeline for a given process ID: it reconstructs the import table of the main executable **and every loaded DLL**, resolves every imported function name, and automatically cross-references each one against a locally cached snapshot of MalAPI.io's own categorization — producing, in one plugin run, exactly the correlation an examiner would otherwise build by hand, function by function, on the live website.

## 4. Contribution and Motivation — stated honestly

There is no academic paper behind this plugin, and its underlying idea — "map known imports to a public category list" — is not itself novel. The contribution here is engineering, not research:

1. **Scope extension beyond the stock plugin.** `windows.iat` reconstructs only the main image's import table. APIMaps generalizes the same VAD-based PE reconstruction technique to every module a process has loaded, using `proc.load_order_modules()`.
2. **A reliable offline dataset that did not previously exist.** MalAPI.io has no public JSON/CSV/API export. The dataset bundled with this plugin (370 functions) was built from MalAPI.io's own published data.
3. **A real correctness bug found and fixed with before/after evidence**, described in Section 8.

## 5. How the Previous Plugin Works

`windows.iat` locates a process's main executable via the 64-bit `_PEB`'s `ImageBaseAddress`, reconstructs that one image from the process's memory layer using a VAD-backed read and `pefile` parsing of the `DIRECTORY_ENTRY_IMPORT` table, and reports the resulting import list. It performs no categorization of the functions it finds, and it does not examine any module other than the main executable.

## 6. How APIMaps Works

For a given process, APIMaps walks `proc.load_order_modules()` — which already correctly enumerates both the 64-bit PEB and, for a WoW64 process, the 32-bit PEB32, and already includes the main executable as one of its own entries — to obtain the base address of every loaded module. For each module, it generalizes the same VAD-based reconstruction `windows.iat` uses for one image to an arbitrary module base, parses its import directory with `pefile`, and deduplicates resolved `(dll, function)` pairs across modules. Each resolved function name is matched against the bundled MalAPI.io dataset — an exact match first, and, only if `--fuzzy` is passed, a secondary "normalized" match that strips a trailing `A`/`W` suffix (e.g. `CreateFileW` → `CreateFileA`), always tagged separately so a lower-confidence match is never silently presented as an exact one.

### Input, Processing, Output — per stage

| Stage | Input | Processing | Output |
|---|---|---|---|
| Module enumeration | A target PID | Walk `load_order_modules()` (covers 64-bit and, if applicable, 32-bit PEB) | List of (module name, base address) for the main image and every loaded DLL |
| Import reconstruction | One module's base address, the process's memory layer | VAD-backed PE reconstruction (`_IMAGE_DOS_HEADER.reconstruct()`) + `pefile` parse of `DIRECTORY_ENTRY_IMPORT` | List of (DLL imported from, function name or ordinal) for that module |
| Deduplication | All modules' import lists for one process | Key on `(dll_name, func_name)`; drop repeats across modules | One deduplicated import list per process |
| Category matching | Each resolved function name, the bundled 370-function dataset | Exact-name lookup; optional normalized A/W-suffix fallback if `--fuzzy` | Category/categories + match type (`exact`/`normalized`) per function, or no match |
| Output | All matched (and, with `--show-all-imports`, unmatched) functions | Render as rows | `TreeGrid`: PID, Process, Module, ImportedFrom, Function, Category, MatchType, Library |

## 7. Testing Process and Setup

- **Dataset acquisition and validation:** the 370-function MalAPI.io snapshot was verified programmatically: 370 unique entries, 0 duplicates, exactly the 8 known MalAPI.io categories represented, 54 functions carrying more than one category.
- **Unit testing:** 13 tests covering dataset integrity (entry count, category coverage, no duplicates) and the exact/fuzzy matching logic, including a test that fuzzy matching never fabricates a match for a name with no plausible counterpart in the dataset.
- **Image-level evaluation, real images only:** `MsMpEng.exe` (PID 1956) and `svchost.exe` (PID 796) on the Volatility public Windows 10 19041 test corpus, and a full, unfiltered 73-process run across the same image. All testing used real, previously acquired memory images; no synthetic image was constructed for this plugin.

## 8. Results and Findings

- `MsMpEng.exe` (PID 1956): 49 matched functions across its main image and loaded DLLs.
- `svchost.exe` (PID 796): 98 matched functions.
- Full-image run (73 processes, no PID filter): 12,723 matched rows, zero crashes.
- **A real bug found and fixed:** an earlier version additionally read the 64-bit PEB's `ImageBaseAddress` to separately locate the "main image" — wrong for a WoW64 (32-bit-on-64-bit) process, since that address is not the process's real 32-bit image base, and redundant for a native process, since `load_order_modules()` already includes the main image. This was found by direct comparison against a real WoW64 process (`ncat.exe`, PID 896, on the `total_recall` image), where both the flawed code and the stock `windows.iat` plugin returned zero rows. After the fix, regression testing on two native processes (`MsMpEng.exe`, `svchost.exe`) produced identical match counts before and after, confirming the fix changed nothing for the non-WoW64 case it wasn't meant to touch. A separate, residual zero-row result on that same WoW64 process after the fix was independently corroborated — not assumed — by reproducing the identical page-fault error using Volatility 3's own stock `windows.pedump` plugin against the same module base address, confirming a page-availability limitation of that specific memory capture rather than a defect in this plugin.
- The most frequently matched functions across the full run (`Sleep`, `GetProcAddress`, `LocalAlloc`, `HeapAlloc`, and similar) are ordinary Windows APIs used by nearly every process on the system — stated here plainly, consistent with Section 9.

## 9. Discussion

APIMaps' engineering value is concentrated in two places: building a reliable offline dataset where none existed in usable form, and extending import-table reconstruction to every loaded module rather than only the main image, which surfaces a materially larger and more complete picture of a process's imported-API surface than the stock plugin provides. The WoW64 bug fix is a genuine correctness improvement, independently corroborated against a second stock plugin rather than taken on faith.

Its central limitation must be stated clearly: a MalAPI.io category match is a correlation aid, not evidence of malice. The most commonly matched functions across a real, unfiltered image run are ubiquitous, benign Windows APIs — exactly what Section 8 reports. An examiner using this plugin's output needs to apply the same judgment they would apply when looking up a function on MalAPI.io by hand; APIMaps automates the lookup, not the interpretation. Two further limitations are scoped explicitly rather than hidden: ordinal-only imports (where no function name is present to match against) are detected but silently excluded from category matching, and dynamically resolved APIs (obtained at runtime via `GetProcAddress` rather than statically imported) are entirely invisible to import-table analysis of this kind.

## 10. Conclusion

APIMaps is a well-engineered automation of a real, publicly documented examiner workflow: it solves a genuine data-acquisition problem (no structured MalAPI.io export exists), extends an existing Volatility 3 technique to a meaningfully larger scope (every loaded module, not just the main image), and includes one real, independently corroborated bug fix. It is presented as exactly that — a practical triage automation with solid engineering behind it — and not as a novel detection technique or a research contribution, because it is neither.
