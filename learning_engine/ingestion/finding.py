import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import storage, validation

def ingest_finding(title, class_id, severity="medium"):
    if not validation.valid_finding(title, class_id):
        return None
    con = storage.connect()
    con.execute("INSERT INTO findings(title,class_id,severity,status) VALUES (?,?,?,?)", (title, class_id, severity, "new"))
    con.commit()
    con.close()
    return True
