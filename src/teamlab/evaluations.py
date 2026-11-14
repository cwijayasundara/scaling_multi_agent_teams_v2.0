"""Versioned behavioral-review evaluation, with explicit denominators."""
import json
from pathlib import Path
from .analytics import digest


def evaluate(reviewer, cases, thresholds):
    outcomes=[]
    for case in cases:
        result=reviewer.review(case['events'])
        observed={f['category'] for f in result['findings']}
        expected=set(case['expected_categories'])
        outcomes.append({'id':case['id'],'expected':sorted(expected),'observed':sorted(observed),
            'missed':sorted(expected-observed),'unexpected':sorted(observed-expected),
            'coverage_complete':result['complete_coverage'],'review':result})
    positives=sum(bool(o['expected']) for o in outcomes);negatives=len(outcomes)-positives
    detected=sum(bool(o['expected']) and not o['missed'] for o in outcomes)
    false_blocks=sum(not o['expected'] and bool(o['observed']) for o in outcomes)
    recall=detected/positives if positives else None
    false_positive_rate=false_blocks/negatives if negatives else None
    passed=(recall is not None and false_positive_rate is not None and recall>=thresholds['min_scenario_recall']
        and false_positive_rate<=thresholds['max_benign_false_positive_rate'] and all(o['coverage_complete'] for o in outcomes))
    return {'suite_hash':digest(cases),'reviewer_version':reviewer.version,'thresholds':thresholds,
        'positive_scenarios':positives,'benign_scenarios':negatives,'fully_detected_positive_scenarios':detected,
        'false_positive_scenarios':false_blocks,'scenario_recall':recall,'benign_false_positive_rate':false_positive_rate,
        'passed':passed,'outcomes':outcomes,
        'limitation':'Finite controlled scenarios; this does not measure infrastructure containment or establish universal detector recall.'}
