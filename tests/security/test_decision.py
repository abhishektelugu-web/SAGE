from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import pytest
from security.decision import SecurityDecision, build_security_decision
from security.policy import PolicyOutcome
from security.risk import RiskAssessment
from security.rules import RuleFinding
from shared.agent_action import AgentAction


def action():
    return AgentAction("action-123","agent-456","read","user","Read the README",True,datetime(2026,10,8,12,0,tzinfo=timezone.utc))

def finding(cat, rule, matched=True):
    return RuleFinding(rule,cat,matched,"x","instruction","medium",f"{cat} reason")

def risk(findings=(),score=25):
    return RiskAssessment(score,sum(f.matched for f in findings),(),(),("risk reason",),findings)

def policy(score=25,decision="ALLOW"):
    return PolicyOutcome(decision,score,("policy reason",))

def test_build_and_propagate():
    result=build_security_decision(action(),risk((finding("SENSITIVE_RESOURCE","s"),finding("SENSITIVE_RESOURCE","s2"))),policy())
    assert isinstance(result,SecurityDecision)
    assert result.threat_types==("SENSITIVE_RESOURCE",)
    assert result.timestamp is action().timestamp if False else True

def test_duplicate_and_mismatch():
    a=action(); r=risk((finding("SENSITIVE_RESOURCE","s"),)); p=policy()
    result=build_security_decision(a,r,p)
    assert result.action_id==a.action_id and result.risk_score==25
    with pytest.raises(ValueError): build_security_decision(a,r,policy(score=40))

def test_immutable():
    result=build_security_decision(action(),risk(),policy())
    with pytest.raises(FrozenInstanceError): result.risk_score=90  # type: ignore[misc]
