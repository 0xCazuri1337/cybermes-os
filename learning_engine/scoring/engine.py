import json, os
W = os.path.join(os.path.dirname(__file__), "signals.json")
DEFAULT = {"novelty": 0.4, "severity": 0.4, "evidence": 0.2}

def load():
    if os.path.exists(W):
        return json.load(open(W))
    return DEFAULT

def score(signals):
    w = load()
    return sum(w.get(k, 0) * v for k, v in signals.items())
