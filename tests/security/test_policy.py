import pytest
from security.policy import evaluate_policy, PolicyOutcome
from security.risk import RiskAssessment
from security.rules import RuleFinding


def f(rule_id, category, severity="medium"):
    return RuleFinding(rule_id=rule_id, category=category, matched=True, matched_text="x", source_field="instruction", severity=severity, reason="reason")

def a(score, findings=()):
    return RiskAssessment(score,len(findings),(),(),(),findings)

@pytest.mark.parametrize(("score","expected"),((0,"ALLOW"),(30,"ALLOW"),(31,"APPROVAL_REQUIRED"),(70,"APPROVAL_REQUIRED"),(71,"BLOCK"),(100,"BLOCK")))
def test_thresholds(score,expected):
    assert evaluate_policy(a(score)).decision==expected

def test_hard_blocks():
    assert evaluate_policy(a(65,(f("s","SENSITIVE_RESOURCE"),f("e","EXTERNAL_EXFILTRATION")))).decision=="BLOCK"
    assert evaluate_policy(a(65,(f("p","PRIVILEGE_ESCALATION"),f("d","DANGEROUS_ACTION")))).decision=="BLOCK"

def test_reasons_and_score_validation():
    out=evaluate_policy(a(40,(f("p","PROMPT_INJECTION","high"),)))
    assert out.decision=="APPROVAL_REQUIRED" and "Prompt injection" in out.reasons[0]
    with pytest.raises(ValueError): evaluate_policy(a(101))
    assert isinstance(out,PolicyOutcome)
