"""Section 13 of the whitepaper must report the threat-coverage numbers exactly as measured."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WHITEPAPER = ROOT / "docs" / "whitepaper" / "whitepaper.md"
FIGURES = ROOT / "docs" / "whitepaper" / "figures.html"
REPORT = json.loads((ROOT / "reports" / "threat-coverage.json").read_text())
CATALOGUE = json.loads((ROOT / "src" / "teamlab" / "threats.json").read_text())

COUNT_ROWS = {"Scenarios run": "scenarios", "Prevented": "prevented", "Detected": "detected",
              "Triaged": "triaged"}
GAP_ROWS = {"Not prevented": "not_prevented", "Not detected": "not_detected"}


def _section_13():
    text = WHITEPAPER.read_text()
    match = re.search(r"^## 13\. Zero Trust posture\n(.*?)(?=^## )", text, re.S | re.M)
    assert match, "whitepaper has no '## 13. Zero Trust posture' section"
    return match.group(1)


def _rows(section):
    """Two-column table rows '| label | value |' keyed by label."""
    return {m.group(1).strip(): m.group(2).strip()
            for m in re.finditer(r"^\|([^|\n]+)\|([^|\n]+)\|\s*$", section, re.M)}


def test_section_13_counts_match_the_coverage_report():
    rows = _rows(_section_13())
    for label, key in COUNT_ROWS.items():
        assert label in rows, f"section 13 has no '{label}' row"
        assert int(re.match(r"\d+", rows[label]).group()) == REPORT["summary"][key], label


def test_section_13_names_exactly_the_reported_gaps():
    rows = _rows(_section_13())
    for label, key in GAP_ROWS.items():
        assert label in rows, f"section 13 has no '{label}' row"
        named = set(re.findall(r"`([a-z0-9-]+)`", rows[label]))
        assert named == set(REPORT["summary"][key]), label


def test_every_scenario_id_named_as_a_gap_is_a_reported_gap():
    section = _section_13()
    gaps = set(REPORT["summary"]["not_prevented"]) | set(REPORT["summary"]["not_detected"])
    for line in section.splitlines():
        if "not detected" in line.lower() or "not prevented" in line.lower():
            ids = {i for i in re.findall(r"`([a-z0-9-]+)`", line) if i in {r["id"] for r in REPORT["results"]}}
            assert ids <= gaps, line


def test_section_13_names_exactly_the_scenarios_without_a_mapping():
    section = _section_13()
    for label, key in (("No OWASP mapping", "owasp_agentic"), ("No MITRE mapping", "mitre")):
        match = re.search(rf"^- {label}: (.*)$", section, re.M)
        assert match, f"section 13 has no '- {label}:' line"
        named = set(re.findall(r"`([a-z0-9-]+)`", match.group(1)))
        assert named == {s["id"] for s in CATALOGUE["scenarios"] if not s[key]}, label


def test_section_13_embeds_the_coverage_figure_and_states_the_pdf_is_stale():
    section = _section_13()
    assert "img/fig12-threat-coverage.png" in section
    assert (WHITEPAPER.parent / "img" / "fig12-threat-coverage.png").is_file()
    assert "the-swarm-we-designed.pdf" in section


def test_figure_12_rows_match_the_report():
    html = FIGURES.read_text()
    match = re.search(r'<section class="fig" id="f12">(.*?)</section>', html, re.S)
    assert match, "figures.html has no f12 section"
    value = {"true": True, "false": False, "null": None}
    rows = {m[0]: (value[m[1]], value[m[2]], value[m[3]], m[4]) for m in re.findall(
        r'\["([a-z0-9-]+)","[^"]*",(true|false|null),(true|false|null),(true|false|null),"([a-z-]+)"\]',
        match.group(1))}
    assert rows == {r["id"]: (r["prevented"], r["detected"], r["triaged"], r["containment"])
                    for r in REPORT["results"]}
