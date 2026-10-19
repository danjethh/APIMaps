"""Unit tests for windows.apimaps.ApiMaps's matching/dataset logic.

These test the plugin's pure-Python pieces (category dataset loading, exact
and normalized name matching, cross-module import dedup) without needing a
real memory image. Image-level testing (does it correctly extract imports
from a real process and emit real matched findings) is done separately in
results/, against real images only, per project convention (see rmfkg_project
and pevad_project's tests for the same split).
"""

import json
import pathlib
import sys

import pytest

PLUGIN_DIR = pathlib.Path(__file__).parent.parent / "plugin" / "windows"
sys.path.insert(0, str(PLUGIN_DIR))

import apimaps  # noqa: E402


@pytest.fixture(scope="module")
def db():
    return apimaps._load_category_db()


def test_dataset_loads_all_370(db):
    assert len(db) == 370


def test_dataset_every_entry_has_at_least_one_category(db):
    for name, entry in db.items():
        assert isinstance(entry["cat"], list)
        assert len(entry["cat"]) >= 1
        assert all(isinstance(c, str) and c for c in entry["cat"])


def test_dataset_categories_match_known_malapi_taxonomy(db):
    expected = {
        "Enumeration",
        "Injection",
        "Evasion",
        "Spying",
        "Internet",
        "Anti-Debugging",
        "Ransomware",
        "Helper",
    }
    seen = set()
    for entry in db.values():
        seen.update(entry["cat"])
    assert seen == expected


def test_known_injection_function_categorized_correctly(db):
    assert db["CreateRemoteThread"]["cat"] == ["Injection"]
    assert db["VirtualAllocEx"]["cat"] == ["Injection"]
    assert db["WriteProcessMemory"]["cat"] == ["Injection"]


def test_known_multi_category_function(db):
    # EnumSystemLocalesA is listed under 4 categories on MalAPI.io
    assert set(db["EnumSystemLocalesA"]["cat"]) == {
        "Injection",
        "Enumeration",
        "Evasion",
        "Ransomware",
    }


def test_exact_match(db):
    kind, data = apimaps.ApiMaps._match(None, "CreateRemoteThread", db, False)
    assert kind == "exact"
    assert data["cat"] == ["Injection"]


def test_no_match_for_unlisted_function(db):
    kind, data = apimaps.ApiMaps._match(None, "TotallyFakeFunctionXYZ", db, False)
    assert kind is None
    assert data is None


def test_no_fuzzy_match_when_fuzzy_disabled(db):
    # CreateFileW isn't in the dataset (only CreateFileA is); fuzzy=False
    # must not match it.
    kind, data = apimaps.ApiMaps._match(None, "CreateFileW", db, False)
    assert kind is None


def test_fuzzy_match_strips_w_suffix_to_a(db):
    kind, data = apimaps.ApiMaps._match(None, "CreateFileW", db, True)
    assert kind == "normalized"
    assert data["cat"] == db["CreateFileA"]["cat"]


def test_fuzzy_match_does_not_fabricate_matches(db):
    # A name with no plausible A/W-stripped counterpart in the dataset must
    # still return no match even with fuzzy enabled.
    kind, data = apimaps.ApiMaps._match(None, "SomeRandomExportW", db, True)
    assert kind is None
    assert data is None


def test_fuzzy_match_never_matches_itself_as_normalized(db):
    # If the exact name already matches, that's reported as "exact", not
    # "normalized" via a degenerate self-strip.
    kind, data = apimaps.ApiMaps._match(None, "ReadFile", db, True)
    assert kind == "exact"


def test_dataset_has_no_duplicate_names():
    with open(PLUGIN_DIR / "apimaps_data.json") as f:
        raw = json.load(f)
    names = [e["name"] for e in raw]
    assert len(names) == len(set(names))


def test_dataset_count_matches_scrape_total():
    with open(PLUGIN_DIR / "apimaps_data.json") as f:
        raw = json.load(f)
    assert len(raw) == 370
