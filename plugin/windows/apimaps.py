# This file is licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
# windows.apimaps.ApiMaps
#
# Given a PID, reconstructs the import table of the process's main executable
# AND every DLL it has loaded (not just the main image, unlike the stock
# windows.iat plugin), then cross-references every resolved imported function
# name against a local snapshot of MalAPI.io's "Associated Attacks"
# categorization (https://malapi.io), so an examiner gets an automatic
# API-to-malicious-behavior correlation for a suspicious process instead of
# manually looking each function up on the site.
#
# This plugin's own name ("APIMaps") and data-file names are ours; the
# category data it ships with is not. MalAPI.io's categorization is credited
# throughout and used as a cited data source, not relabeled as our own.
#
# Data acquisition note: MalAPI.io has no public JSON/CSV export (its "Export
# Table" button only renders an html2canvas PNG screenshot of the table, not
# structured data) and the site is not reachable at plugin runtime (examiners
# analyzing malware memory images are routinely offline/air-gapped, and this
# plugin must not depend on live internet access regardless). apimaps_data.json
# bundled alongside this plugin is therefore a static, locally cached snapshot
# of all 370 functions MalAPI.io listed at acquisition time (2026-10-19),
# scraped from the site's own per-function detail pages
# (https://malapi.io/winapi/<FunctionName>), which expose each function's
# Associated Attacks categorization in clean, unambiguous markup. The
# categorization itself is MalAPI.io's own (credited to mr.d0x and
# contributors); this plugin does not invent or re-derive it.

import json
import logging
import pathlib
import io
from typing import Dict

import pefile

from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

_DATA_FILE = pathlib.Path(__file__).parent / "apimaps_data.json"


def _load_category_db() -> Dict[str, Dict]:
    """Loads the bundled MalAPI.io snapshot into an exact-name lookup dict,
    keyed by the function name as MalAPI.io spells it."""
    with open(_DATA_FILE, "r") as f:
        entries = json.load(f)
    db = {}
    for e in entries:
        db[e["name"]] = {"cat": e["cat"], "lib": e.get("lib", "")}
    return db


class ApiMaps(interfaces.plugins.PluginInterface):
    """Extracts every API function a process has imported (main executable
    plus all loaded DLLs) and cross-references each one against a local
    snapshot of MalAPI.io's malicious-behavior categorization."""

    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process ID(s) to analyze. If omitted, every process is analyzed "
                "(this is read-only and can be slow on large images).",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="show_all_imports",
                description="Also show imported functions that have NO MalAPI.io category match "
                "(default: only matched functions are shown, to keep output focused).",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="fuzzy",
                description="Also report a lower-confidence 'normalized' match for imports whose "
                "exact name isn't in the MalAPI.io dataset but matches after stripping "
                "a trailing 'A' or 'W' suffix (e.g. CreateFileW -> CreateFileA). Off by "
                "default so results are exact-match-only unless asked for.",
                default=False,
                optional=True,
            ),
        ]

    @staticmethod
    def _reconstruct_pe(context, config_path, proc_layer_name, base_address):
        """Reconstructs a PE image (main executable OR any loaded DLL, given
        its in-memory base address) from a process's memory layer, the same
        VAD-based reconstruction technique windows.iat and windows.pedump use
        for the main image, generalized here to an arbitrary module base so
        every loaded module's import table can be walked, not just the
        process's main executable."""
        pe_table_name = intermed.IntermediateSymbolTable.create(
            context, config_path, "windows", "pe", class_types=pe.class_types
        )
        pe_data = io.BytesIO()
        dos_header = context.object(
            pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
            offset=base_address,
            layer_name=proc_layer_name,
        )
        for offset, data in dos_header.reconstruct():
            pe_data.seek(offset)
            pe_data.write(data)
        return pefile.PE(data=pe_data.getvalue(), fast_load=True)

    def _imports_for_module(self, context, config_path, proc_layer_name, base_address):
        """Returns [(dll_name, function_name_or_None, ordinal_or_None), ...]
        for one module's import table. Exceptions are the caller's problem to
        report, not silently swallow."""
        pe_obj = self._reconstruct_pe(
            context, config_path, proc_layer_name, base_address
        )
        pe_obj.parse_data_directories(
            [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        results = []
        if hasattr(pe_obj, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="replace") if entry.dll else "?"
                for imp in entry.imports:
                    if imp.name:
                        results.append((dll_name, imp.name.decode(errors="replace"), None))
                    else:
                        results.append((dll_name, None, imp.ordinal))
        return results

    def _match(self, func_name: str, db: Dict, fuzzy: bool):
        """Exact match first; optionally a normalized (A/W-suffix-stripped)
        fallback match, clearly tagged with which kind it is so results are
        never silently overclaimed."""
        if func_name in db:
            return "exact", db[func_name]
        if fuzzy and func_name and func_name[-1] in ("A", "W"):
            stripped = func_name[:-1]
            for candidate in (stripped + "A", stripped):
                if candidate in db and candidate != func_name:
                    return "normalized", db[candidate]
        return None, None

    def _generator(self, procs):
        db = _load_category_db()
        show_all = self.config.get("show_all_imports", False)
        fuzzy = self.config.get("fuzzy", False)

        for proc in procs:
            proc_id = proc.UniqueProcessId
            proc_name = proc.ImageFileName.cast(
                "string", max_length=proc.ImageFileName.vol.count, errors="replace"
            )
            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                vollog.warning(f"PID {proc_id}: could not add process layer")
                continue
            if proc_layer_name is None:
                vollog.warning(f"PID {proc_id}: add_process_layer returned None")
                continue

            # Collect (module_name, base_address) for the main image + every
            # loaded DLL. proc.load_order_modules() already walks BOTH the
            # 64-bit PEB and (for a WoW64 process) the 32-bit PEB32, and
            # already includes the main executable itself as one of its
            # entries -- confirmed against windows.dlllist output. An earlier
            # version of this plugin additionally read peb.ImageBaseAddress
            # (the 64-bit PEB only) to get the "main image" base; that is
            # wrong for a WoW64 process (it is not the real 32-bit image
            # base) and redundant for a native process (load_order_modules()
            # already yields the main image). Verified by comparing against
            # windows.dlllist.DllList and the stock windows.iat.IAT plugin on
            # a real WoW64 process (ncat.exe, total_recall image, PID 896):
            # both the old code here and the stock windows.iat plugin return
            # zero rows for that process, while dlllist correctly lists its
            # (32-bit-addressed) modules -- so this was a real, verified gap
            # in the PEB.ImageBaseAddress approach, not a hypothetical one.
            modules = []
            try:
                for entry in proc.load_order_modules():
                    try:
                        mod_name = entry.FullDllName.get_string()
                    except exceptions.InvalidAddressException:
                        mod_name = renderers.UnreadableValue()
                    try:
                        base = entry.DllBase
                        if base:
                            modules.append((mod_name, base))
                    except exceptions.InvalidAddressException:
                        continue
            except exceptions.InvalidAddressException:
                vollog.debug(f"PID {proc_id}: loader module list unreadable")

            seen_functions = set()
            for mod_label, base_address in modules:
                try:
                    imports = self._imports_for_module(
                        self.context, self.config_path, proc_layer_name, base_address
                    )
                except (exceptions.InvalidAddressException, ValueError, pefile.PEFormatError) as excp:
                    vollog.debug(
                        f"PID {proc_id} module {mod_label} @ {base_address:#x}: "
                        f"import table not reconstructable ({excp})"
                    )
                    continue

                for dll_name, func_name, ordinal in imports:
                    if func_name is None:
                        # Ordinal-only import: no name to cross-reference.
                        continue
                    dedupe_key = (dll_name, func_name)
                    if dedupe_key in seen_functions:
                        continue
                    seen_functions.add(dedupe_key)

                    match_kind, match_data = self._match(func_name, db, fuzzy)
                    if match_data is None:
                        if not show_all:
                            continue
                        yield (
                            0,
                            (
                                proc_id,
                                proc_name,
                                mod_label,
                                dll_name,
                                func_name,
                                "",
                                "",
                                "",
                            ),
                        )
                    else:
                        yield (
                            0,
                            (
                                proc_id,
                                proc_name,
                                mod_label,
                                dll_name,
                                func_name,
                                ", ".join(match_data["cat"]),
                                match_kind,
                                match_data.get("lib", ""),
                            ),
                        )

    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Module", str),
                ("ImportedFrom", str),
                ("Function", str),
                ("Category", str),
                ("MatchType", str),
                ("Library", str),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                    filter_func=pslist.PsList.create_pid_filter(
                        self.config.get("pid", None)
                    ),
                )
            ),
        )
