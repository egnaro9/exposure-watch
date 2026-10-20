"""Tests for the parts that involve no model: versions, baseline, verifier, scoring."""
import json
from pathlib import Path

import pytest

from exposure_watch import agents
from exposure_watch.baseline import judge
from exposure_watch.data import load_inventory, sources_for
from exposure_watch.pipeline import outcome, run, summarize
from exposure_watch.verify import check
from exposure_watch.versions import compare, in_range, split_update

ROOT = Path(__file__).resolve().parent.parent
INV = {i.id: i for i in load_inventory(ROOT / "examples" / "inventory.csv")}
from exposure_watch.key import load_pairs
PAIRS = load_pairs(with_errata=True)


# --- versions -----------------------------------------------------------------

@pytest.mark.parametrize("a,b,want", [
    ("17.9.4", "17.9.4a", -1),        # rebuild suffix sorts after the base
    ("13.1-49.13", "13.1-49.15", -1),  # build numbers after the dash
    ("2.14.1", "2.15.0", -1),
    ("15.1.4", "15.1.5.1", -1),
    ("22.0.9", "22.0.9", 0),
    ("2.0-beta9", "2.0.1", -1),        # pre-release sorts before release
])
def test_compare(a, b, want):
    assert compare(a, b) == want
    assert compare(b, a) == -want


def test_end_excluding_is_exclusive():
    assert not in_range("22.0.9", start="22.0.0", end="22.0.9")
    assert in_range("22.0.8", start="22.0.0", end="22.0.9")


@pytest.mark.parametrize("vendor,product,written,want", [
    ("Microsoft", "Exchange Server", "2019 CU8", ("2019", "cumulative_update_8")),
    ("Palo Alto Networks", "PAN-OS", "10.2.9-h1", ("10.2.9", "h1")),
    ("Palo Alto Networks", "PAN-OS", "10.2.9", ("10.2.9", "-")),
    ("Ivanti", "Connect Secure", "22.6R2", ("22.6", "r2")),
    ("Apache", "Log4j", "2.14.1", ("2.14.1", "*")),
])
def test_split_update(vendor, product, written, want):
    assert split_update(vendor, product, written) == want


# --- baseline -----------------------------------------------------------------

def test_baseline_misses_exactly_what_a_cpe_row_cannot_say():
    """The baseline reads only CPE rows, which can say neither "depends on a
    feature" nor "the documents disagree". So it should be wrong on exactly the
    conditional and unknown pairs, and right everywhere else."""
    wrong = {(p["item"], p["cve"]) for p in PAIRS if judge(INV[p["item"]], p["cve"])[0] != p["truth"]}
    inexpressible = {(p["item"], p["cve"]) for p in PAIRS if p["truth"] in ("conditional", "unknown")}
    assert wrong == inexpressible and len(wrong) >= 2


# --- verifier -----------------------------------------------------------------

def _src():
    return sources_for(INV["inv-19"], "CVE-2023-27350")


def test_real_quote_survives():
    ans = {"cve": "CVE-2023-27350", "verdict": "affected", "claims": [
        {"text": "range", "source": "nvd_config", "quote": "versionEndExcluding=22.0.9"}]}
    c = check(ans, "CVE-2023-27350", _src())
    assert c.supported and len(c.kept) == 1


@pytest.mark.parametrize("claim,reason", [
    ({"text": "x", "source": "nvd_config", "quote": "versionEndExcluding=22.0.10"}, "quote not found"),
    ({"text": "x", "source": "vendor_advisory", "quote": "fixed in 22.0.9 and later"}, "unknown source"),
    ({"text": "x", "source": "kev", "quote": "versionEndExcluding=22.0.9"}, "quote not found"),
    ({"text": "see CVE-2099-12345", "source": "nvd_config", "quote": "versionEndExcluding=22.0.9"}, "absent from every source"),
])
def test_bad_evidence_is_dropped(claim, reason):
    c = check({"cve": "CVE-2023-27350", "verdict": "affected", "claims": [claim]}, "CVE-2023-27350", _src())
    assert not c.kept and reason in c.dropped[0]["reason"]
    assert not c.supported


def test_wrong_cve_is_a_problem():
    c = check({"cve": "CVE-2023-27351", "verdict": "unknown", "claims": []}, "CVE-2023-27350", _src())
    assert any("not CVE-2023-27350" in p for p in c.problems)


def test_a_wrong_verdict_with_real_quotes_passes_the_verifier():
    """Stated limit, pinned: the verifier checks evidence, not conclusions."""
    ans = {"cve": "CVE-2023-27350", "verdict": "not_affected", "claims": [
        {"text": "range", "source": "nvd_config", "quote": "versionEndExcluding=22.0.9"}]}
    assert check(ans, "CVE-2023-27350", _src()).supported


# --- scoring ------------------------------------------------------------------

@pytest.mark.parametrize("final,truth,want", [
    ("affected", "affected", "correct"), ("needs_human", "affected", "escalated"),
    ("affected", "conditional", "overcalled"), ("conditional", "affected", "undercalled"),
    ("affected", "not_affected", "false_alarm"), ("not_affected", "affected", "missed"),
    ("not_affected", "conditional", "missed"),
    ("needs_human", "unknown", "correct"), ("affected", "unknown", "overconfident"),
])
def test_outcome(final, truth, want):
    assert outcome(final, truth) == want


def test_pipeline_replays_recorded_answers(tmp_path):
    """End to end on recorded answers: a skeptic disagreement escalates, and a
    fabricated quote is stopped by the verifier before the skeptic sees it."""
    item, cve = INV["inv-19"], "CVE-2023-27350"
    k = f"{item.id}__{cve}"
    good = {"cve": cve, "verdict": "affected", "claims": [
        {"text": "range", "source": "nvd_config", "quote": "versionEndExcluding=22.0.9"}]}
    agents.save(tmp_path / "triage", k, {"answer": good, "cost_usd": 0.01, "latency_s": 2.0, "model": "fake"})
    agents.save(tmp_path / "skeptic", k, {"answer": {"agree": False, "verdict": "not_affected", "reason": "r",
                                                    "source": "nvd_config", "quote": "q"},
                                         "cost_usd": 0.02, "latency_s": 3.0, "model": "fake"})
    rs = run([{"item": item.id, "cve": cve, "truth": "affected"}], INV, tmp_path)
    by = {r.shape: r for r in rs}
    assert by["code"].outcome == "correct" and by["agent"].outcome == "correct"
    assert by["agent+verify"].outcome == "correct"
    assert by["agent+verify+skeptic"].final == "needs_human"
    assert summarize(rs)["agent+verify+skeptic"]["cost_usd"] == pytest.approx(0.03)


def test_missing_recording_fails_loudly(tmp_path):
    with pytest.raises(FileNotFoundError, match="do not substitute"):
        run([{"item": "inv-19", "cve": "CVE-2023-27350", "truth": "affected"}], INV, tmp_path)


class _Counting:
    """A stand-in backend: answers 'affected' and counts how often it is asked."""

    def __init__(self, model):
        self.model, self.calls = model, 0

    def ask(self, system, prompt, schema):
        self.calls += 1
        return {"answer": {"cve": "x", "verdict": "affected", "claims": []}, "cost_usd": 0.0,
                "latency_s": 0.0, "requested_model": self.model, "model": self.model}


def test_rerun_reuses_saved_answers(tmp_path):
    b = _Counting("sonnet")
    first = agents.fetch(b, tmp_path, "k", "s", "p", {})
    again = agents.fetch(b, tmp_path, "k", "s", "p", {})
    assert b.calls == 1 and first == again


def test_run_dir_cannot_mix_models(tmp_path):
    agents.fetch(_Counting("sonnet"), tmp_path, "k", "s", "p", {})
    with pytest.raises(RuntimeError, match="fresh --run directory"):
        agents.fetch(_Counting("opus"), tmp_path, "k", "s", "p", {})


def test_every_row_describing_an_item_reaches_the_agent():
    from exposure_watch.retrieval import recall
    r = recall(PAIRS, INV)
    assert r["relevant_rows"] > 0 and r["kept"] == r["relevant_rows"]
    assert not r["pairs_with_a_dropped_row"] and not r["pairs_with_no_relevant_row"]


class _Rejects:
    """A skeptic that accepts nothing."""
    model = "fake"

    def ask(self, system, prompt, schema):
        return {"answer": {"agree": False, "verdict": "unknown", "reason": "r", "source": "kev", "quote": "q"},
                "cost_usd": 0.0, "latency_s": 0.0, "requested_model": "fake", "model": "fake"}


def test_a_skeptic_that_rejects_everything_shows_up_in_the_control_column(tmp_path):
    """Catching every flip is worthless if correct answers are rejected too, and
    the control column is what exposes it."""
    from exposure_watch.planted import run_skeptic_side
    t = run_skeptic_side(PAIRS, INV, tmp_path, _Rejects())
    assert t["verdict_flipped"]["not_accepted"] == t["verdict_flipped"]["shown"] > 0
    assert t["control"]["not_accepted"] == t["control"]["shown"]


def _errata_file(tmp_path, monkeypatch, entries):
    from exposure_watch import key
    f = tmp_path / "errata.json"
    f.write_text(json.dumps({"errata": entries}))
    monkeypatch.setattr(key, "ERRATA", f)
    return key


def test_an_erratum_must_state_the_label_it_replaces(tmp_path, monkeypatch):
    key = _errata_file(tmp_path, monkeypatch, [{"item": "inv-01", "cve": "CVE-2021-44228",
                                                 "was": "not_affected", "now": "unknown", "why": "w"}])
    with pytest.raises(ValueError, match="says it was"):
        key.load_pairs()


def test_an_erratum_for_a_pair_not_in_the_key_fails(tmp_path, monkeypatch):
    key = _errata_file(tmp_path, monkeypatch, [{"item": "inv-99", "cve": "CVE-2099-0001",
                                                 "was": "affected", "now": "unknown", "why": "w"}])
    with pytest.raises(ValueError, match="not in the key"):
        key.load_pairs()


def test_errata_change_only_the_named_pair_and_keep_the_frozen_key(tmp_path, monkeypatch):
    key = _errata_file(tmp_path, monkeypatch, [{"item": "inv-01", "cve": "CVE-2021-44228",
                                                 "was": "affected", "now": "unknown", "why": "w"}])
    fixed, frozen = key.load_pairs(), key.load_pairs(with_errata=False)
    diff = [(a["item"], a["truth"], b["truth"]) for a, b in zip(fixed, frozen) if a["truth"] != b["truth"]]
    assert diff == [("inv-01", "unknown", "affected")]


def test_a_saved_answer_is_not_reused_for_a_changed_question(tmp_path):
    agents.fetch(_Counting("sonnet"), tmp_path, "k", "s", "prompt one", {})
    with pytest.raises(RuntimeError, match="different question"):
        agents.fetch(_Counting("sonnet"), tmp_path, "k", "s", "prompt two", {})


def test_reference_answers_cite_the_row_that_decides_them():
    """An affected reference must quote a row whose range holds the version; a
    not_affected one must quote a row of the same product that does not."""
    from exposure_watch.planted import reference_answer
    from exposure_watch.baseline import ALIASES
    from exposure_watch.versions import split_update
    checked = 0
    for p in PAIRS:
        item, cve = INV[p["item"]], p["cve"]
        ans = reference_answer(item, cve, p["truth"])
        if ans is None or ans["verdict"] not in ("affected", "not_affected"):
            continue
        row = ans["claims"][0]["quote"]
        crit, *bounds = row.split(" | ")
        f = crit.split(":")
        assert f"{f[3]}:{f[4]}" in ALIASES[(item.vendor, item.product)], (p, row)
        b = dict(x.split("=", 1) for x in bounds)
        version, update = split_update(item.vendor, item.product, item.version)
        if b:
            inside = in_range(version, b.get("versionStartIncluding") or b.get("versionStartExcluding") or "",
                              "versionStartIncluding" in b,
                              b.get("versionEndIncluding") or b.get("versionEndExcluding") or "",
                              "versionEndIncluding" in b)
        else:
            inside = compare(version, f[5]) == 0 and f[6] in ("*", update)
        assert inside == (ans["verdict"] == "affected"), (p, row)
        checked += 1
    assert checked == sum(p["truth"] in ("affected", "not_affected") for p in PAIRS)


# --- data sets ----------------------------------------------------------------

def test_the_keyword_rule_is_frozen():
    """eval/heldout/PREREG.md measures this exact rule. Changing it voids the held-out result."""
    import re
    from exposure_watch.baseline import CONDITION
    assert CONDITION.pattern == r"\bfeature\b|\bwhen configured\b|\bconfigured as\b|\bwhen exposed\b"
    assert CONDITION.flags & re.I


@pytest.fixture
def toy_set(tmp_path, monkeypatch):
    """A one-vulnerability data set, switched to after the original set's caches are warm."""
    from exposure_watch import data
    fx = tmp_path / "fixtures"
    (fx / "nvd").mkdir(parents=True)
    (fx / "kev_catalog.json").write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2099-0001", "vendorProject": "Acme", "product": "Widget"}]}))
    (fx / "nvd" / "CVE-2099-0001.json").write_text(json.dumps({"vulnerabilities": [{"cve": {
        "descriptions": [{"lang": "en", "value": "toy description"}],
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True,
            "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}]}]}]}}]}))
    (tmp_path / "inventory.csv").write_text("id,vendor,product,version,where\nt-1,Acme,Widget,1.5,h\n")
    (tmp_path / "key.json").write_text(json.dumps({"pairs": [
        {"item": "t-1", "cve": "CVE-2099-0001", "truth": "affected"}]}))
    (tmp_path / "aliases.json").write_text(json.dumps({"aliases": [
        {"vendor": "Acme", "product": "Widget", "nvd": ["acme:widget"]}]}))
    monkeypatch.setitem(data.SETS, "toy", data.DataSet(
        "toy", fx, tmp_path / "inventory.csv", tmp_path / "key.json",
        tmp_path / "errata.json", tmp_path / "aliases.json"))
    data.use("original")
    data.kev_index()
    yield data.use("toy")
    data.use("original")


def test_switching_sets_reloads_the_catalog(toy_set):
    from exposure_watch import data
    assert "CVE-2099-0001" in data.kev_index()
    assert "CVE-2021-44228" not in data.kev_index()
    assert data.nvd_description("CVE-2099-0001") == "toy description"


def test_set_aliases_extend_the_table_and_reach_the_matcher(toy_set):
    from exposure_watch.baseline import aliases
    from exposure_watch.data import Item
    table = aliases()
    assert table[("Acme", "Widget")] == ["acme:widget"]
    assert ("Apache", "Log4j") in table
    assert judge(Item("t-1", "Acme", "Widget", "1.5", "h"), "CVE-2099-0001")[0] == "affected"
    assert judge(Item("t-2", "Acme", "Widget", "2.0", "h"), "CVE-2099-0001")[0] == "not_affected"


def test_the_key_follows_the_set(toy_set):
    from exposure_watch import key
    assert [(p["item"], p["truth"]) for p in key.load_pairs()] == [("t-1", "affected")]


def test_the_original_set_comes_back_after_a_switch(toy_set):
    from exposure_watch import data, key
    data.use("original")
    assert "CVE-2021-44228" in data.kev_index()
    assert len(key.load_pairs()) == 22


def test_the_heldout_key_is_the_one_frozen_before_the_run():
    """PREREG.md records the key's hash. Editing the key after the run is what errata.json is for."""
    import hashlib
    import re
    prereg = (ROOT / "eval" / "heldout" / "PREREG.md").read_text(encoding="utf-8")
    want = re.search(r"ground_truth\.json`: sha256 `([0-9a-f]{64})`", prereg).group(1)
    got = hashlib.sha256((ROOT / "eval" / "heldout" / "ground_truth.json").read_bytes()).hexdigest()
    assert got == want


def test_every_heldout_pair_has_its_item_and_documents():
    from exposure_watch import data, key
    try:
        data.use("heldout")
        inv = {i.id: i for i in load_inventory(data.current().inventory)}
        pairs = key.load_pairs()
        assert len(pairs) == 57
        for p in pairs:
            item = inv[p["item"]]
            assert p["cve"] in data.kev_index()
            assert data.nvd_config_text(p["cve"], item), p
    finally:
        data.use("original")


def test_heldout_reference_answers_rest_on_verbatim_key_quotes():
    """Held-out references come from the labelers' quotes, not the tuned keyword
    rule, and each one must pass the verifier before it is mutated."""
    from exposure_watch import data, key
    from exposure_watch.planted import key_evidence, run_verifier_side
    try:
        data.use("heldout")
        inv = {i.id: i for i in load_inventory(data.current().inventory)}
        ev = key_evidence()
        assert len(ev) == 57
        tally = run_verifier_side(key.load_pairs(), inv, ev)
        assert "skipped_no_verbatim_key_quote" not in tally
        assert tally["wrong_source"] == {"planted": 57, "caught_by_verifier": 57}
        assert tally["verdict_flipped"]["caught_by_verifier"] == 0
    finally:
        data.use("original")
