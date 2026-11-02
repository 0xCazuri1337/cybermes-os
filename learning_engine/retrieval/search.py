import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import storage

def search(q):
    con = storage.connect()
    rows = con.execute("SELECT title,class_id,severity,status FROM findings WHERE title LIKE ? OR class_id LIKE ?", (f"%{q}%", f"%{q}%")).fetchall()
    con.close()
    return rows
