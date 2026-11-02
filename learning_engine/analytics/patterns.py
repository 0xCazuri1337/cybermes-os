import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import storage

def patterns():
    con = storage.connect()
    rows = con.execute("SELECT class_id, COUNT(*) FROM findings GROUP BY class_id").fetchall()
    con.close()
    return rows
