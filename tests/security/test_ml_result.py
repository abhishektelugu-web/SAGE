from dataclasses import FrozenInstanceError
import pytest
from shared.ml_result import MLDetectionResult


def test_malicious_and_benign_results():
    x=MLDetectionResult(is_malicious=True,confidence=.95,threat_type="PROMPT_INJECTION",reasons=("override",),model_name="detector-v1")
    y=MLDetectionResult(is_malicious=False,confidence=.1,threat_type=None,reasons=("safe",),model_name="detector-v1")
    assert x.reason=="override" and y.threat_type is None

@pytest.mark.parametrize("c",(0.0,1.0))
def test_confidence_edges(c):
    assert MLDetectionResult(is_malicious=False,confidence=c,threat_type=None,reasons=(),model_name="m").confidence==c

@pytest.mark.parametrize("c",(-.1,1.1,True))
def test_bad_confidence(c):
    with pytest.raises((TypeError,ValueError)): MLDetectionResult(is_malicious=False,confidence=c,threat_type=None,reasons=(),model_name="m")

def test_legacy_threats_are_normalized():
    assert MLDetectionResult(is_malicious=True,confidence=.8,threat_type="DATA_EXFILTRATION",reason="x").threat_type=="EXTERNAL_EXFILTRATION"
    assert MLDetectionResult(is_malicious=False,confidence=.1,threat_type="SAFE",reason="x").threat_type is None

def test_invalid_threat_rejected():
    with pytest.raises(ValueError): MLDetectionResult(is_malicious=True,confidence=.8,threat_type="UNKNOWN_THREAT",reason="x")

def test_immutable():
    x=MLDetectionResult(is_malicious=True,confidence=.8,threat_type="PROMPT_INJECTION",reason="x")
    with pytest.raises(FrozenInstanceError): x.confidence=.1  # type: ignore[misc]
