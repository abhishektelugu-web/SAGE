from security.risk import calculate_risk, RiskAssessment
from security.rules import RuleFinding
from shared.threats import ThreatCategory
import pytest


def finding(rule_id="TEST_RULE", category: ThreatCategory="PROMPT_INJECTION", severity="low", matched=True):
    return RuleFinding(rule_id=rule_id, category=category, matched=matched, matched_text="matched test text", source_field="instruction", severity=severity, reason="A test indicator was detected.")


def test_no_findings_zero():
    result=calculate_risk(())
    assert result.risk_score==0 and result.finding_count==0 and result.reasons==()

@pytest.mark.parametrize(("severity","score"), (("low",10),("medium",25),("high",40)))
def test_severity_scoring(severity, score):
    assert calculate_risk((finding(severity=severity),)).risk_score==score

def test_multiple_and_cap():
    assert calculate_risk((finding("a",severity="high"),finding("b",severity="medium"))).risk_score==65
    assert calculate_risk((finding(f"h{i}",severity="high") for i in range(3))).risk_score==100

def test_duplicate_rule_id_only_counts_once():
    result=calculate_risk((finding("same",severity="high"),finding("same",severity="high")))
    assert result.risk_score==40 and result.finding_count==1

def test_unmatched_ignored():
    assert calculate_risk((finding(matched=False,severity="high"),)).risk_score==0

def test_reasons_explain():
    result=calculate_risk((finding("PROMPT_OVERRIDE",severity="high"),))
    assert "40 points" in result.reasons[0]


def test_assessment_structure():
    result=calculate_risk((finding("P",severity="high"),finding("S",category="SENSITIVE_RESOURCE",severity="medium")))
    assert isinstance(result,RiskAssessment)
    assert result.severity_counts==(('medium',1),('high',1))
