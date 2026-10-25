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
    ("2.4", "2.4.0", 0),               # trailing zeros name the same release
    ("17.9.4", "17.9.4.0", 0),
    ("2.4", "2.4.1", -1),              # ...but any other tail still sorts after
    ("2.0-beta9", "2.0", -1),          # a pre-release comes before its release
    ("2.0-rc2", "2.0", -1),
    ("2.0-alpha1", "2.0", -1),
    ("2.0.0-rc1", "2.0", -1),          # zeros before the tag do not change that
    ("2.0-alpha1", "2.0-beta1", -1),
    ("2.0-beta8", "2.0-beta9", -1),
    ("2.0-rc1", "2.0-patch1", -1),     # a pre-release tag sorts before other letters, so the order
    ("2.0-rc1", "2.0a", -1),           # stays total: 2.0-rc1 < 2.0 < 2.0-patch1
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
    ("Apache", "Log4j", "2.0-beta9", ("2.0", "beta9")),
    ("Apache", "Log4j", "2.0-rc2", ("2.0", "rc2")),
    ("Apache", "Log4j", "2.0.beta9", ("2.0", "beta9")),
    ("Apache", "Log4j", "2.0beta9", ("2.0", "beta9")),
    ("Apache", "Log4j", "2.0-RC2", ("2.0", "rc2")),
    ("Apache", "Log4j", "2.0-alpha1", ("2.0", "alpha1")),
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


@pytest.mark.parametrize("version,want", [
    ("2.0-beta9", "affected"),
    ("2.0-rc2", "affected"),
    ("2.0.beta9", "affected"),
    ("2.0beta9", "affected"),
    ("2.4", "affected"),        # NVD's range starts at 2.4.0
    ("2.14.1", "affected"),
    ("2.17.1", "not_affected"),
])
def test_log4j_prereleases_are_judged_against_their_own_rows(version, want):
    """2.0-beta9 is the first release Log4Shell hits, and NVD lists it as
    log4j:2.0:beta9. The inventory only held 2.14.1 and 2.17.1, so nothing caught
    the pre-releases coming back not_affected: the miss the README calls expensive."""
    from exposure_watch.data import Item
    assert judge(Item("l-1", "Apache", "Log4j", version, "h"), "CVE-2021-44228")[0] == want


PRE_ROW = {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
           "versionStartIncluding": "2.0-beta9", "versionEndExcluding": "2.15.0"}


@pytest.mark.parametrize("version,want", [
    ("2.0-beta8", "not_affected"), ("2.0beta8", "not_affected"),
    ("2.0-beta9", "affected"), ("2.0-rc1", "affected"), ("2.0", "affected"),
    ("2.14.1", "affected"), ("2.15.0", "not_affected"),
])
def test_a_range_that_starts_at_a_prerelease(monkeypatch, version, want):
    """No fixture has such a range, so this one is made up: a bound written as a
    pre-release is compared with the item's full version, not its bare base."""
    from exposure_watch import baseline
    from exposure_watch.data import Item
    monkeypatch.setattr(baseline, "vulnerable_rows", lambda cve: [PRE_ROW])
    assert judge(Item("l-1", "Apache", "Log4j", version, "h"), "CVE-2099-0002")[0] == want


@pytest.mark.parametrize("version,want", [
    ("14.1 8.50", "not_affected"),     # the first fixed 14.1 build, written with a space
    ("13.1 49.15", "not_affected"),
    ("13.1 49.13", "affected"),
])
def test_a_build_written_after_a_space_stays_part_of_the_version(version, want):
    """NetScaler bounds carry the build (versionEndExcluding=14.1-8.50). Read
    with a space, the build must still count, or a fixed box reads as exposed."""
    from exposure_watch.data import Item
    assert judge(Item("c-1", "Citrix", "NetScaler ADC", version, "h"), "CVE-2023-4966")[0] == want


def test_nearest_row_for_a_prerelease_below_every_exact_row():
    """Log4j 2.0-beta8 sits below every 2.0 row Log4Shell lists, so the nearest
    row is the range that starts lowest, never an exact 2.0 row above it."""
    from exposure_watch import baseline
    from exposure_watch.data import Item
    row = baseline.nearest_row(Item("l-1", "Apache", "Log4j", "2.0-beta8", "h"), "CVE-2021-44228")
    assert "versionStartIncluding=2.0.1" in row and ":2.0:" not in row


def test_nearest_row_for_a_range_that_starts_at_a_prerelease(monkeypatch):
    """An item just below a pre-release start bound: the closest row is that range."""
    from exposure_watch import baseline
    from exposure_watch.data import Item, config_line
    monkeypatch.setattr(baseline, "vulnerable_rows", lambda cve: [PRE_ROW])
    item = Item("l-1", "Apache", "Log4j", "2.0-beta8", "h")
    assert baseline.nearest_row(item, "CVE-2099-0002") == config_line(PRE_ROW)


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


def _replay_one(tmp_path, answer, review):
    """Record one triage answer and one skeptic review for inv-19, replay, return results by shape."""
    item, cve = INV["inv-19"], "CVE-2023-27350"
    k = f"{item.id}__{cve}"
    agents.save(tmp_path / "triage", k, {"answer": answer, "cost_usd": 0.01, "latency_s": 2.0,
                                         "model": "fake-triage"})
    agents.save(tmp_path / "skeptic", k, {"answer": review, "cost_usd": 0.02, "latency_s": 3.0,
                                          "model": "fake-skeptic"})
    return {r.shape: r for r in run([{"item": item.id, "cve": cve, "truth": "affected"}], INV, tmp_path)}


REAL_ROW = {"text": "range", "source": "nvd_config", "quote": "versionEndExcluding=22.0.9"}


def test_a_flagged_answer_goes_to_a_person_even_if_the_skeptic_agrees(tmp_path):
    """An answer about the wrong CVE that quotes real text is flagged by the
    verifier, and a flag sends it to a person: it never reaches the skeptic,
    whose agreement could otherwise wave it through."""
    by = _replay_one(tmp_path, {"cve": "CVE-2023-27351", "verdict": "affected", "claims": [REAL_ROW]},
                     {"agree": True, "verdict": "affected", "reason": "the row covers it",
                      "source": "nvd_config", "quote": "versionEndExcluding=22.0.9"})
    assert by["agent"].final == "affected"
    assert by["agent+verify"].final == "needs_human" and "not CVE-2023-27350" in by["agent+verify"].note
    assert by["agent+verify+skeptic"].final == "needs_human"
    assert by["agent+verify+skeptic"].cost_usd == pytest.approx(0.01)   # the skeptic was never asked
    assert by["agent+verify+skeptic"].skeptic_model == ""               # so no skeptic model answered


@pytest.mark.parametrize("agree,verdict,reason,quote,want,note", [
    # a real passage: agreement counts
    (True, "affected", "the row covers it", "versionEndExcluding=22.0.9", "affected", "the row covers it"),
    # the reason is prose and is not screened, so naming a related CVE is fine
    (True, "affected", "unlike CVE-2099-11111", "versionEndExcluding=22.0.9", "affected", "unlike CVE-2099-11111"),
    # agreeing with a different verdict is not agreement
    (True, "not_affected", "the row covers it", "versionEndExcluding=22.0.9", "needs_human", "the row covers it"),
    # a quote in no document: agreement does not count, and the note says why
    (True, "affected", "the row covers it", "versionEndExcluding=22.0.10", "needs_human",
     "the row covers it (skeptic's quote dropped: quote not found in nvd_config)"),
    (True, "affected", "the row covers it", None, "needs_human", "quote too short to check"),
    # a disagreement keeps the skeptic's objection in the note, quote or no quote
    (False, "not_affected", "the fix is installed", "an invented passage", "needs_human", "the fix is installed"),
])
def test_skeptic_agreement_needs_the_same_verdict_and_a_real_skeptic_quote(tmp_path, agree, verdict, reason,
                                                                           quote, want, note):
    by = _replay_one(tmp_path, {"cve": "CVE-2023-27350", "verdict": "affected", "claims": [REAL_ROW]},
                     {"agree": agree, "verdict": verdict, "reason": reason, "source": "nvd_config", "quote": quote})
    assert by["agent+verify"].final == "affected"
    assert by["agent+verify+skeptic"].final == want
    assert note in by["agent+verify+skeptic"].note


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


class _AgreesQuoting:
    """A skeptic that says it agrees with whatever it is shown. It quotes the
    analyst's own passage, or a sentence no document contains ("invent"), or
    quotes the real passage but names another verdict ("other_verdict")."""
    model = "fake"

    def __init__(self, mode):
        self.mode = mode

    def ask(self, system, prompt, schema):
        ans = json.loads(prompt.split("ANALYST ANSWER TO REVIEW:\n", 1)[1])
        claim = ans["claims"][0]
        quote = "a sentence that appears in no document" if self.mode == "invent" else claim["quote"]
        verdict = ans["verdict"]
        if self.mode == "other_verdict":
            verdict = "unknown" if verdict != "unknown" else "affected"
        return {"answer": {"agree": True, "verdict": verdict, "reason": "r",
                           "source": claim["source"], "quote": quote},
                "cost_usd": 0.0, "latency_s": 0.0, "requested_model": "fake", "model": "fake"}


@pytest.mark.parametrize("mode,accepts_all", [("own_quote", True), ("invent", False), ("other_verdict", False)])
def test_planted_skeptic_rejects_an_invented_quote_or_another_verdict(tmp_path, mode, accepts_all):
    """Acceptance is decided as in the pipeline: a skeptic that agrees with
    everything accepts every answer, flips included, unless its quote is not in
    the documents or it names another verdict, and then it accepts none."""
    from exposure_watch.planted import run_skeptic_side
    t = run_skeptic_side(PAIRS, INV, tmp_path, _AgreesQuoting(mode))
    for kind in ("control", "verdict_flipped"):
        assert t[kind]["shown"] > 0
        assert t[kind]["not_accepted"] == (0 if accepts_all else t[kind]["shown"])


def test_planted_verifier_table_matches_the_readme():
    """The verifier column of the README's planted table, pinned. Each evidence
    defect counts as caught only if the pipeline would act on it."""
    from exposure_watch.planted import run_verifier_side
    t = run_verifier_side(PAIRS, INV)
    assert {k: (v["planted"], v["caught_by_verifier"]) for k, v in t.items()} == {
        "quote_altered": (19, 19), "wrong_source": (22, 22), "invented_cve": (22, 22),
        "wrong_cve": (22, 22), "verdict_flipped": (22, 0)}


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
    with data.using("heldout") as ds:
        inv = {i.id: i for i in load_inventory(ds.inventory)}
        pairs = key.load_pairs()
        assert len(pairs) == 57
        for p in pairs:
            item = inv[p["item"]]
            assert p["cve"] in data.kev_index()
            assert data.nvd_config_text(p["cve"], item), p


def test_heldout_reference_answers_rest_on_verbatim_key_quotes():
    """Held-out references come from the labelers' quotes, not the tuned keyword
    rule, and each one must pass the verifier before it is mutated."""
    from exposure_watch import data, key
    from exposure_watch.planted import key_evidence, run_verifier_side
    with data.using("heldout") as ds:
        inv = {i.id: i for i in load_inventory(ds.inventory)}
        ev = key_evidence()
        assert len(ev) == 57
        tally = run_verifier_side(key.load_pairs(), inv, ev)
        assert "skipped_no_verbatim_key_quote" not in tally
        assert tally["wrong_source"] == {"planted": 57, "caught_by_verifier": 57}
        assert tally["wrong_cve"] == {"planted": 57, "caught_by_verifier": 57}
        assert tally["verdict_flipped"]["caught_by_verifier"] == 0


# --- round trip and matcher versioning ----------------------------------------

def _vendor_spelling(vendor, product, version, update):
    """How the vendor itself writes a (version, update), where split_update has a
    rule for that vendor: 10.2.9-h1, 22.6R2, 2019 CU8, 2.0-beta9."""
    if product.lower() == "pan-os":
        return f"{version}-{update}"
    if vendor.lower() == "ivanti" and update.startswith("r"):
        return f"{version}R{update[1:]}"
    if update.startswith("cumulative_update_"):
        return f"{version} CU{update.rsplit('_', 1)[1]}"
    if product.lower() == "log4j":
        return f"{version}-{update}"
    return None


def _round_trip_failures():
    """Every vulnerable row of a product the alias tables know, in every NVD
    record of both sets, judged on its own. An exact row (version, update) is
    written as tools/heldout_build.py writes an item ("3.5.0 patch3") and, where
    split_update has a rule for that vendor, as the vendor writes it ("10.2.9-h1").
    A range row is tried at each bound b and at b.0. Inside must come back
    affected and outside must not. Rows of products with no alias are skipped:
    the matcher answers "unknown" for those by design."""
    from exposure_watch import baseline, data
    from exposure_watch.data import Item, vulnerable_rows
    fails, checked = [], 0
    for name in ("original", "heldout"):
        with data.using(name) as ds:
            by_nvd = {}
            for (vendor, product), names in baseline.aliases().items():
                for n in names:
                    by_nvd.setdefault(n, (vendor, product))
            for cve in sorted(p.stem for p in (ds.fixtures / "nvd").glob("*.json")):
                for row in vulnerable_rows(cve):
                    f = row["criteria"].split(":")
                    if f"{f[3]}:{f[4]}" not in by_nvd:
                        continue
                    vendor, product = by_nvd[f"{f[3]}:{f[4]}"]
                    if any(row.get(k) for k in baseline._RANGE_KEYS):
                        cases = [(w, k.endswith("Including"))
                                 for k in baseline._RANGE_KEYS if row.get(k)
                                 for w in (row[k], row[k] + ".0")]
                    elif f[5] not in ("*", "-"):
                        spellings = {f[5] if f[6] in ("*", "-") else f"{f[5]} {f[6]}",
                                     _vendor_spelling(vendor, product, f[5], f[6]) if f[6] not in ("*", "-") else None}
                        cases = [(w, True) for w in sorted(spellings - {None})]
                    else:
                        continue
                    for written, inside in cases:
                        checked += 1
                        got = _judge_one_row(baseline, row, Item("rt", vendor, product, written, "h"), cve)
                        if (got == "affected") != inside:
                            fails.append(f"{name} {cve} {vendor} {product} {written!r}: {got}")
    return checked, fails


def _judge_one_row(baseline, row, item, cve):
    orig = baseline.vulnerable_rows
    baseline.vulnerable_rows = lambda c: [row]
    try:
        return baseline.judge(item, cve)[0]
    finally:
        baseline.vulnerable_rows = orig


def test_every_fixture_row_round_trips_through_the_matcher():
    """The property that would have caught both version-format misses before a
    run: Log4j 2.0-beta9 and the held-out Cisco ISE item ho-53, "3.5.0 patch3"."""
    checked, fails = _round_trip_failures()
    assert checked > 1000
    assert not fails, f"{len(fails)} of {checked} fail, e.g. {fails[:5]}"


def test_ise_patch_is_split_into_nvds_two_fields():
    assert split_update("Cisco", "Identity Services Engine", "3.5.0 patch3") == ("3.5.0", "patch3")


def _toy_run(tmp_path, verdicts=None):
    """inv-19 with one recorded triage answer and skeptic review, and optionally a matcher.json."""
    item, cve = INV["inv-19"], "CVE-2023-27350"
    k = f"{item.id}__{cve}"
    agents.save(tmp_path / "triage", k, {"answer": {"cve": cve, "verdict": "affected", "claims": [REAL_ROW]},
                                         "cost_usd": 0.01, "latency_s": 1.0, "model": "fake"})
    agents.save(tmp_path / "skeptic", k, {"answer": {"agree": False, "verdict": "unknown", "reason": "r",
                                                    "source": "kev", "quote": "q"},
                                         "cost_usd": 0.01, "latency_s": 1.0, "model": "fake"})
    if verdicts is not None:
        (tmp_path / "matcher.json").write_text(json.dumps(
            {"commit": "abc1234", "sha256": "0" * 64, "verdicts": verdicts}))
    return [{"item": item.id, "cve": cve, "truth": "affected"}], k


def test_a_replay_scores_the_code_from_the_recorded_matcher(tmp_path):
    """A published code verdict stays published: the replay reads it from
    matcher.json, and only matcher='current' asks today's code."""
    pairs, k = _toy_run(tmp_path, {})
    (tmp_path / "matcher.json").write_text(json.dumps({"commit": "abc1234", "sha256": "0" * 64, "verdicts": {
        k: {"code": ["not_affected", "recorded"], "code+keywords": ["not_affected", "recorded"]}}}))
    frozen = {r.shape: r for r in run(pairs, INV, tmp_path)}
    now = {r.shape: r for r in run(pairs, INV, tmp_path, matcher="current")}
    assert frozen["code"].final == "not_affected" and frozen["code"].note == "recorded"
    assert now["code"].final == "affected"
    from exposure_watch.pipeline import changed, matcher_header
    assert changed(list(frozen.values()), list(now.values())) == [
        "inv-19 CVE-2023-27350 code: not_affected -> affected",
        "inv-19 CVE-2023-27350 code+keywords: not_affected -> affected"]
    assert matcher_header(tmp_path, "recorded")["commit"] == "abc1234"
    assert matcher_header(tmp_path, "current")["matcher"] == "current code"


def test_a_recorded_matcher_missing_a_pair_fails_loudly(tmp_path):
    pairs, k = _toy_run(tmp_path, {})
    with pytest.raises(KeyError, match="do not substitute"):
        run(pairs, INV, tmp_path)


def test_a_live_run_records_its_matcher(tmp_path):
    from exposure_watch.pipeline import matcher_sha256, recorded_matcher
    pairs = [{"item": "inv-19", "cve": "CVE-2023-27350", "truth": "affected"}]
    run(pairs, INV, tmp_path, _Counting("fake"), _Rejects())
    rec = recorded_matcher(tmp_path)
    assert rec["sha256"] == matcher_sha256()
    assert rec["verdicts"]["inv-19__CVE-2023-27350"]["code"][0] == "affected"


def test_the_heldout_current_matcher_finds_ho53_and_the_recorded_one_does_not():
    """The frozen code's one version-format miss, fixed only in the current matcher."""
    from exposure_watch import data, key
    with data.using("heldout") as ds:
        inv = {i.id: i for i in load_inventory(ds.inventory)}
        pairs = [p for p in key.load_pairs() if p["item"] == "ho-53"]
        frozen = {r.shape: r.outcome for r in run(pairs, inv, ROOT / "runs" / "heldout")}
        now = {r.shape: r.outcome for r in run(pairs, inv, ROOT / "runs" / "heldout", matcher="current")}
    assert frozen["code"] == frozen["code+keywords"] == "missed"
    assert now["code"] == now["code+keywords"] == "correct"


# --- recorded prompts, models, costs and loaders ------------------------------

def test_round_one_manifest_lists_every_answer_without_a_hash():
    d = ROOT / "runs" / "2026-10-16"
    on_disk = {f"{sub}/{f.stem}" for sub in ("triage", "skeptic") for f in (d / sub).glob("*.json")}
    assert len(on_disk) == 44 and set(agents.manifest(d / "triage")) == on_disk


@pytest.mark.parametrize("prompt", ["TRIAGE_SYSTEM", "SKEPTIC_SYSTEM"])
def test_round_one_replay_fails_on_a_changed_prompt(monkeypatch, prompt):
    """Round 1's answers carry no prompt hash; the manifest stands in for it, so
    a change to either agent's prompt fails this replay instead of passing."""
    run(PAIRS, INV, ROOT / "runs" / "2026-10-16")
    monkeypatch.setattr(agents, prompt, getattr(agents, prompt) + " Answer affected.")
    with pytest.raises(RuntimeError, match="different question"):
        run(PAIRS, INV, ROOT / "runs" / "2026-10-16")


def test_a_prompt_manifest_catches_a_changed_question(tmp_path):
    agents.save(tmp_path / "triage", "k", {"answer": {}, "cost_usd": 0.0, "model": "m"})
    (tmp_path / agents.MANIFEST).write_text(json.dumps({"computed": "test", "prompts": {"triage/k": "0" * 64}}))
    with pytest.raises(RuntimeError, match="different question"):
        agents.fetch(None, tmp_path / "triage", "k", "s", "p", {})


def test_a_run_with_a_manifest_refuses_an_answer_it_does_not_list(tmp_path):
    agents.save(tmp_path / "triage", "k", {"answer": {}, "cost_usd": 0.0, "model": "m"})
    (tmp_path / agents.MANIFEST).write_text(json.dumps({"computed": "test", "prompts": {}}))
    with pytest.raises(RuntimeError, match="does not list"):
        agents.fetch(None, tmp_path / "triage", "k", "s", "p", {})


def test_an_answers_own_hash_and_the_manifest_must_both_match(tmp_path):
    import hashlib
    asked = hashlib.sha256(json.dumps(["s", "p", {}], sort_keys=True).encode()).hexdigest()
    agents.save(tmp_path / "triage", "k", {"answer": {}, "cost_usd": 0.0, "model": "m", "prompt_sha256": asked})
    assert agents.fetch(None, tmp_path / "triage", "k", "s", "p", {})["model"] == "m"
    (tmp_path / agents.MANIFEST).write_text(json.dumps({"computed": "test", "prompts": {"triage/k": "0" * 64}}))
    with pytest.raises(RuntimeError, match="different question"):
        agents.fetch(None, tmp_path / "triage", "k", "s", "p", {})


def test_a_live_rerun_will_not_reuse_an_answer_with_no_cost(tmp_path):
    import hashlib
    asked = hashlib.sha256(json.dumps(["s", "p", {}], sort_keys=True).encode()).hexdigest()
    agents.save(tmp_path, "k", {"answer": {}, "cost_usd": None, "requested_model": "sonnet", "model": "m",
                                "prompt_sha256": asked})
    with pytest.raises(ValueError, match="no cost"):
        agents.fetch(_Counting("sonnet"), tmp_path, "k", "s", "p", {})


def test_a_live_call_that_reports_no_cost_is_not_saved(monkeypatch, tmp_path):
    import subprocess

    class Done:
        returncode, stderr = 0, ""
        stdout = json.dumps({"structured_output": {"verdict": "unknown"}, "modelUsage": {"m": {}}})

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Done())
    with pytest.raises(RuntimeError, match="no cost"):
        agents.fetch(agents.ClaudeCLI("m"), tmp_path, "k", "s", "p", {})
    assert not (tmp_path / "k.json").exists()


def test_a_live_call_will_not_reuse_an_answer_with_no_prompt_hash(tmp_path):
    agents.save(tmp_path, "k", {"answer": {}, "cost_usd": 0.0, "requested_model": "sonnet", "model": "m"})
    with pytest.raises(RuntimeError, match="no prompt hash"):
        agents.fetch(_Counting("sonnet"), tmp_path, "k", "s", "p", {})
    assert agents.fetch(None, tmp_path, "k", "s", "p", {})["model"] == "m"   # a pure replay still reads it


def test_a_recorded_answer_with_no_cost_fails_loudly(tmp_path):
    agents.save(tmp_path, "k", {"answer": {}, "cost_usd": None, "model": "m"})
    with pytest.raises(ValueError, match="no cost"):
        agents.fetch(None, tmp_path, "k", "s", "p", {})


def test_live_defaults_are_full_model_ids():
    """An alias such as "sonnet" moves to a newer model without notice."""
    from exposure_watch.__main__ import parser
    run_args = parser().parse_args(["run", "--run", "x"])
    planted_args = parser().parse_args(["planted"])
    assert (run_args.triage_model, run_args.skeptic_model) == ("claude-sonnet-5", "claude-opus-5")
    assert planted_args.skeptic_model == "claude-opus-5"


def test_results_carry_the_model_that_answered(tmp_path):
    by = _replay_one(tmp_path, {"cve": "CVE-2023-27350", "verdict": "affected", "claims": [REAL_ROW]},
                     {"agree": True, "verdict": "affected", "reason": "r", "source": "nvd_config",
                      "quote": "versionEndExcluding=22.0.9"})
    assert by["code"].triage_model == ""
    assert by["agent"].triage_model == by["agent+verify"].triage_model == "fake-triage"
    assert (by["agent+verify+skeptic"].triage_model, by["agent+verify+skeptic"].skeptic_model) == (
        "fake-triage", "fake-skeptic")


def test_aliases_ignore_case_everywhere():
    from exposure_watch.baseline import names_for, nearest_row
    from exposure_watch.data import Item
    from exposure_watch.retrieval import recall
    assert names_for("apache", "LOG4J") == names_for("Apache", "Log4j") == ["apache:log4j"]
    low = {"l-1": Item("l-1", "apache", "log4j", "2.14.1", "h")}
    assert judge(low["l-1"], "CVE-2021-44228")[0] == "affected"
    assert recall([{"item": "l-1", "cve": "CVE-2021-44228"}], low)["relevant_rows"] > 0
    fixed = Item("l-2", "apache", "log4j", "2.17.1", "h")
    assert nearest_row(fixed, "CVE-2021-44228") == nearest_row(
        Item("l-2", "Apache", "Log4j", "2.17.1", "h"), "CVE-2021-44228") != ""


def test_an_unaliased_product_has_no_names_and_raises_nothing():
    from exposure_watch.baseline import names_for, nearest_row
    from exposure_watch.data import Item
    from exposure_watch.retrieval import recall
    item = Item("u-1", "Nobody", "Nothing", "1.0", "h")
    assert names_for(item.vendor, item.product) == []
    assert judge(item, "CVE-2021-44228") == ("unknown", "no alias for this product")
    assert nearest_row(item, "CVE-2021-44228") == ""
    assert recall([{"item": "u-1", "cve": "CVE-2021-44228"}], {"u-1": item})["pairs_with_no_relevant_row"]


def test_an_edited_alias_file_is_read_again(toy_set):
    import os
    from exposure_watch.baseline import names_for
    f = toy_set.aliases
    assert names_for("Acme", "Widget") == ["acme:widget"]
    f.write_text(json.dumps({"aliases": [{"vendor": "Acme", "product": "Widget", "nvd": ["acme:w2"]}]}))
    st = f.stat()
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    assert names_for("Acme", "Widget") == ["acme:w2"]


def test_using_restores_the_set_before_even_after_an_error():
    from exposure_watch import data
    with pytest.raises(RuntimeError):
        with data.using("heldout"):
            assert data.current().name == "heldout"
            raise RuntimeError("boom")
    assert data.current().name == "original" and "CVE-2021-44228" in data.kev_index()


def test_using_nests_and_restores_the_set_it_found():
    from exposure_watch import data
    with data.using("heldout"):
        with data.using("original"):
            assert data.current().name == "original"
        assert data.current().name == "heldout"
    assert data.current().name == "original"


def test_planted_skeptic_refuses_recorded_answers_no_reference_matches(tmp_path):
    """If a matcher change stops a reference answer being built, its recorded
    answers must not silently drop out of the tally."""
    from exposure_watch.planted import run_skeptic_side
    agents.save(tmp_path / "planted_skeptic", "inv-99__CVE-2099-0001__control",
                {"answer": {}, "cost_usd": 0.0, "model": "m"})
    with pytest.raises(RuntimeError, match="no reference answer"):
        run_skeptic_side(PAIRS, INV, tmp_path)


def test_switching_sets_reloads_nvd_records(tmp_path, monkeypatch):
    """A CVE in both sets must come from the set in use, not from the cache."""
    from exposure_watch import data
    fx = tmp_path / "fixtures"
    (fx / "nvd").mkdir(parents=True)
    (fx / "nvd" / "CVE-2021-44228.json").write_text(json.dumps({"vulnerabilities": [{"cve": {
        "descriptions": [{"lang": "en", "value": "another set's text"}], "configurations": []}}]}))
    monkeypatch.setitem(data.SETS, "twin", data.DataSet("twin", fx, tmp_path / "i.csv", tmp_path / "k.json",
                                                        tmp_path / "e.json"))
    assert data.nvd_description("CVE-2021-44228") != "another set's text"
    with data.using("twin"):
        assert data.nvd_description("CVE-2021-44228") == "another set's text"
    assert data.nvd_description("CVE-2021-44228") != "another set's text"
