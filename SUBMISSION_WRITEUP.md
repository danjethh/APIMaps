# APIMaps — Volatility Foundation 14th Annual Plugin Contest Submission

## What it is

APIMaps (`windows.apimaps.ApiMaps`) is a Volatility 3 plugin that, given a
PID, reconstructs the import table of a process's main executable **and
every DLL it has loaded**, then cross-references every resolved imported
function name against a local snapshot of MalAPI.io's malicious-behavior
categorization (Enumeration, Injection, Evasion, Spying, Internet,
Anti-Debugging, Ransomware, Helper). An examiner who has flagged a
suspicious process gets an automatic API-to-malicious-behavior correlation
instead of manually looking each unfamiliar function up on malapi.io by
hand. Unlike PEVAD and rMFKG, this submission has no academic paper behind
it — it automates an existing manual workflow using an existing public
dataset and an existing Volatility3 technique, rather than implementing
published research.

## How it's used

    vol -p ./plugin -f image.dmp windows.apimaps.ApiMaps [--pid N ...] \
        [--show-all-imports] [--fuzzy]

Output is the standard Volatility 3 TreeGrid: one row per
(process, module, imported function) with its MalAPI.io category/categories,
match type (`exact` or, with `--fuzzy`, `normalized`), and library. Full
usage and the dataset's provenance are in the repository README.

## Why it's useful, reported plainly about its limits

1. **It goes beyond Volatility3's own `windows.iat`.** The stock plugin only
   reconstructs the main executable's import table. This one generalizes the
   same VAD-reconstruction + `pefile` technique across every loaded module
   (`proc.load_order_modules()`), because the actual imported-API surface of
   a process is everything it has loaded, not just its main image.

2. **A real correctness bug was found and fixed with before/after evidence.**
   An earlier version additionally read the 64-bit PEB's `ImageBaseAddress`
   to get the "main image" base — wrong for a WoW64 (32-bit-on-64-bit)
   process and redundant for a native one, since `load_order_modules()`
   already walks both the 64-bit PEB and the 32-bit PEB32 and already
   includes the main image. Found by direct comparison against a real WoW64
   process (`ncat.exe`, PID 896, `total_recall` image), where both the old
   code and the stock `windows.iat` plugin returned zero rows. Fixed by
   dropping the redundant/wrong code path; verified the fix changes nothing
   for native (non-WoW64) processes (identical row counts before/after on
   two separate processes on `win10_19041`).

3. **A separate, residual gap on that same WoW64 process was investigated,
   not hand-waved.** After the fix, `ncat.exe` still returns zero import
   rows. Root-caused by testing Volatility3's own stock `windows.pedump`
   plugin against the exact same module base address — it fails with the
   identical `Page Fault ... in page entry` error, confirming this is a
   page-availability limitation of this specific capture for this
   short-lived process, not a defect in this plugin's logic.

4. **Verified against real images only**, including a full 73-process,
   zero-crash run on `win10_19041` producing 12,723 matched rows.

5. **Honest reporting of what a match does and doesn't mean.** The most
   frequently matched functions across that full run (`Sleep`,
   `GetProcAddress`, `LocalAlloc`, `HeapAlloc`, ...) are ordinary, common
   Windows APIs used by nearly every process — stated plainly in the README
   and `results/SUMMARY.md` rather than presented as if a match were
   evidence of malice. This is a triage/correlation aid, not a verdict.

## Data provenance (why this needed real engineering, not a copy-paste)

MalAPI.io has no public JSON/CSV/API export; its own "Export Table" button
renders an `html2canvas` PNG screenshot of the table, not structured data
(confirmed by reading the function's own minified source on the live site).
The homepage table's HTML also does not map cleanly to one-row-per-function
(confirmed empirically via contradictory column-indexed scrapes). The
bundled dataset (`apimaps_data.json`, 370 functions) was instead built by
scraping each function's own `/winapi/<name>` detail page, which has an
unambiguous `Associated Attacks` field, and cross-checked against MalAPI.io's
own table-screenshot export of the same data. It ships as a static,
locally-cached file — this plugin never depends on live internet access at
scan time.

## Repository

Plugin, 13 passing unit tests, real-image evaluation (full-image run,
targeted process tests, the WoW64 bug-fix evidence), README with the
dataset provenance and honest scope notes: see `README.md` and
`results/SUMMARY.md` in this submission.

## Is this meaningful/valuable enough for a paper?

No, not as it stands. It's a well-engineered automation of a manual lookup
with a genuinely found-and-fixed bug, which has real value to examiners —
but there's no novel detection technique or research contribution here. It
applies an existing public dataset (MalAPI.io's categorization) to an
existing Volatility3 technique (import-table reconstruction, which
`windows.iat` already does for the main image). PEVAD and rMFKG each
implement or extend published research; this one doesn't have that angle,
and padding it into a paper would overstate what it is.

## License

Not yet finalized — this plugin's license will be determined pending the
outcome of this contest, per the repository README.
