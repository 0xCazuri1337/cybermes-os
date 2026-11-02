import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import storage, validation

def triage(title, class_id, severity):
    if not validation.valid_finding(title, class_id):
        return "rejected"
    return "accepted"
