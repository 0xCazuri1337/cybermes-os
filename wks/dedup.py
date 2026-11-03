"""Phase 6: Knowledge Deduplication & Conflict-Safe Consolidation."""
from __future__ import annotations

import difflib
import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

RELATIONSHIPS = ("EXACT_DUPLICATE","SEMANTIC_NEAR_DUPLICATE","COMPLEMENTARY","CONTEXT_DEPENDENT","POTENTIAL_CONTRADICTION","UNRELATED","UNCERTAIN")
PROPOSAL_STATUSES = ("PENDING_REVIEW","APPROVED","APPLIED","REJECTED","DEFERRED")
MODES = ("AUDIT","PROPOSE","REVIEW","APPLY")
NEGATION_WORDS = {"not","no","never","none","cannot","can't","cant","without","isn't","isnt","aren't","arent","doesn't","doesnt","don't","dont","won't","wont","shouldn't","shouldnt","mustn't","mustnt","false","disabled","absent","missing","fail","fails","failed"}

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def normalize_text(text):
    if text is None: return ""
    s=str(text).lower()
    s=re.sub(r"[^a-z0-9\s]"," ",s)
    s=re.sub(r"\s+"," ",s).strip()
    return s

def _tokens(text):
    return [t for t in normalize_text(text).split() if len(t)>=2]

def _ngrams(text,n=3):
    s=normalize_text(text).replace(" ","")
    if len(s)<n: return {s} if s else set()
    return {s[i:i+n] for i in range(len(s)-n+1)}

def polarity(text):
    toks=_tokens(text)
    neg=sum(1 for t in toks if t in NEGATION_WORDS)
    return -1 if (neg%2==1 and neg>0) else (1 if neg==0 else 0)

def has_negation(text):
    return any(t in NEGATION_WORDS for t in _tokens(text))

def fingerprint(text_or_item, *, class_id=None):
    if isinstance(text_or_item,dict):
        claim=text_or_item.get("claim") or text_or_item.get("text") or ""
        cls=class_id or text_or_item.get("class_id")
    else:
        claim=getattr(text_or_item,"claim",None)
        if claim is None:
            try: claim=text_or_item["claim"]
            except Exception: claim=str(text_or_item)
        cls=class_id
        try:
            if cls is None and hasattr(text_or_item,"get"): cls=text_or_item.get("class_id")
        except Exception: pass
    norm=normalize_text(claim)
    if cls: norm=f"{cls}::{norm}"
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()

def _item_claim(item):
    if isinstance(item,dict): return item.get("claim") or item.get("text") or ""
    try: return item["claim"]
    except Exception:
        try: return item.get("claim","")
        except Exception: return str(item)

def _item_class(item):
    if isinstance(item,dict): return item.get("class_id")
    try: return item["class_id"]
    except Exception:
        try: return item.get("class_id")
        except Exception: return None

def _item_id(item):
    if isinstance(item,dict): return item.get("id")
    try: return item["id"]
    except Exception:
        try: return item.get("id")
        except Exception: return None

def extract_scope(text):
    s=str(text or "")
    m=re.search(r"\bscope[d]?[:=]\s*([A-Za-z0-9_\-./]+)",s,re.I)
    if m: return m.group(1)
    m=re.search(r"\b(?:in|for|on)\s+(tenant|user|account|org|organization|session|role|admin|authenticated|unauthenticated)\b",s,re.I)
    if m: return m.group(1).lower()
    return None

def extract_version(text):
    s=str(text or "")
    m=re.search(r"v\d+(?:\.\d+)*",s,re.I)
    if m: return m.group(0).lower()
    m=re.search(r"version\s+(\d+(?:\.\d+)*)",s,re.I)
    if m: return m.group(1)
    return None

def extract_preconditions(text):
    s=str(text or "")
    return [m.group(0).strip() for m in re.finditer(r"\b(?:if|when|unless|requires?|precondition|assuming)\b[^.;]*",s,re.I)]

def _seq_ratio(a,b):
    return difflib.SequenceMatcher(None,normalize_text(a),normalize_text(b)).ratio()

def _token_jaccard(a,b):
    ta,tb=set(_tokens(a)),set(_tokens(b))
    if not ta or not tb: return 0.0
    return len(ta&tb)/len(ta|tb)

def _ngram_jaccard(a,b,n=3):
    ga,gb=_ngrams(a,n),_ngrams(b,n)
    if not ga or not gb: return 0.0
    return len(ga&gb)/len(ga|gb)

def semantic_similarity(a,b,*,con=None,class_aware=True):
    ca,cb=_item_claim(a),_item_claim(b)
    score=0.0
    score+=0.4*_seq_ratio(ca,cb)
    score+=0.3*_token_jaccard(ca,cb)
    score+=0.2*_ngram_jaccard(ca,cb,3)
    if class_aware:
        if _item_class(a) is not None and _item_class(a)==_item_class(b):
            score=min(1.0,score+0.1)
        else:
            score=max(0.0,score-0.05)
    return round(min(1.0,max(0.0,score)),4)

def _protection(a,b):
    reasons=[]
    ca,cb=_item_claim(a),_item_claim(b)
    sa,sb=extract_scope(ca),extract_scope(cb)
    va,vb=extract_version(ca),extract_version(cb)
    pa,pb=extract_preconditions(ca),extract_preconditions(cb)
    if sa and sb and sa!=sb: reasons.append("scope")
    if va and vb and va!=vb: reasons.append("version")
    if pa and pb and pa!=pb: reasons.append("preconditions")
    pol_a,pol_b=polarity(ca),polarity(cb)
    if pol_a!=0 and pol_b!=0 and pol_a!=pol_b: reasons.append("polarity")
    neg_a,neg_b=has_negation(ca),has_negation(cb)
    if neg_a!=neg_b: reasons.append("negation")
    return {"protected":bool(reasons),"reasons":reasons,
            "scope_diff":bool(sa and sb and sa!=sb),
            "version_diff":bool(va and vb and va!=vb),
            "preconditions_diff":bool(pa and pb and pa!=pb),
            "polarity_diff":bool(pol_a!=0 and pol_b!=0 and pol_a!=pol_b),
            "negation_diff":bool(neg_a!=neg_b)}

def classify_relationship(a,b,*,con=None,sim=None):
    if sim is None: sim=semantic_similarity(a,b,con=con,class_aware=True)
    fa,fb=fingerprint(a),fingerprint(b)
    if fa==fb: return "EXACT_DUPLICATE"
    prot=_protection(a,b)
    opposite_pol = (polarity(_item_claim(a))!=0 and polarity(_item_claim(b))!=0 and polarity(_item_claim(a))!=polarity(_item_claim(b))) or (has_negation(_item_claim(a))!=has_negation(_item_claim(b)))
    if sim>=0.88:
        if opposite_pol:
            return "CONTEXT_DEPENDENT" if prot["protected"] else "POTENTIAL_CONTRADICTION"
        return "SEMANTIC_NEAR_DUPLICATE"
    if sim>=0.6:
        if prot["protected"]: return "CONTEXT_DEPENDENT"
        if opposite_pol: return "POTENTIAL_CONTRADICTION"
        if _token_jaccard(_item_claim(a),_item_claim(b))>=0.3: return "COMPLEMENTARY"
        return "UNCERTAIN"
    if sim>=0.35: return "UNCERTAIN"
    return "UNRELATED"

import sqlite3
def store_fingerprint(con,item):
    iid=_item_id(item); cls=_item_class(item); claim=_item_claim(item); fp=fingerprint(item)
    cur=con.execute("""INSERT INTO dedup_fingerprint(item_id,class_id,fingerprint,normalized,polarity,scope,version,preconditions,created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
        (iid,cls,fp,normalize_text(claim),polarity(claim),extract_scope(claim),extract_version(claim),json.dumps(extract_preconditions(claim)),now()))
    con.commit(); return cur.lastrowid

def find_exact_duplicates(con,item=None):
    if item is None:
        rows=con.execute("SELECT fingerprint,COUNT(*) c FROM dedup_fingerprint GROUP BY fingerprint HAVING c>1").fetchall()
        out=[]
        for r in rows:
            fps=con.execute("SELECT * FROM dedup_fingerprint WHERE fingerprint=?",(r["fingerprint"],)).fetchall()
            out.append({"fingerprint":r["fingerprint"],"items":[dict(x) for x in fps]})
        return out
    fp=fingerprint(item)
    rows=con.execute("SELECT * FROM dedup_fingerprint WHERE fingerprint=? AND item_id<>?",(fp,_item_id(item))).fetchall()
    return [dict(r) for r in rows]

def audit(con,*,class_id=None):
    q="SELECT * FROM item WHERE status='active'"; params=[]
    if class_id:
        q+=" AND class_id=?"; params.append(class_id)
    items=[dict(r) for r in con.execute(q,params).fetchall()]
    pairs=[]
    for i in range(len(items)):
        for j in range(i+1,len(items)):
            a,b=items[i],items[j]
            if class_id and (a["class_id"]!=class_id or b["class_id"]!=class_id): continue
            sim=semantic_similarity(a,b,con=con,class_aware=True)
            rel=classify_relationship(a,b,con=con,sim=sim)
            if rel!="UNRELATED":
                pairs.append({"item_a":a["id"],"item_b":b["id"],"class_a":a["class_id"],"class_b":b["class_id"],"similarity":sim,"relationship":rel,"protection":_protection(a,b)})
    return {"mode":"AUDIT","items_scanned":len(items),"pairs":pairs,
            "exact_duplicates":[p for p in pairs if p["relationship"]=="EXACT_DUPLICATE"],
            "potential_contradictions":[p for p in pairs if p["relationship"]=="POTENTIAL_CONTRADICTION"]}

def propose(con,item_ids,*,relationship="SEMANTIC_NEAR_DUPLICATE",rationale=None,mode="PROPOSE"):
    ids=[int(x) for x in item_ids]
    key="mp-"+uuid.uuid4().hex[:12]
    gkey="cg-"+uuid.uuid4().hex[:12]
    cur=con.execute("INSERT INTO canonical_group(group_key,canonical_item_id,status,created_at,updated_at) VALUES (?,?,?,?,?)",(gkey,ids[0] if ids else None,"PENDING_REVIEW",now(),now()))
    gid=cur.lastrowid
    for iid in ids:
        con.execute("INSERT OR IGNORE INTO item_group(item_id,group_id,role) VALUES (?,?,?)",(iid,gid,"canonical" if iid==ids[0] else "member"))
    cur=con.execute("""INSERT INTO merge_proposal(proposal_key,group_id,item_ids,relationship,status,mode,rationale,created_at) VALUES (?,?,?,?,?,?,?,?)""",(key,gid,json.dumps(ids),relationship,"PENDING_REVIEW",mode,rationale,now()))
    pid=cur.lastrowid
    con.commit()
    return {"proposal_id":pid,"proposal_key":key,"group_id":gid,"status":"PENDING_REVIEW"}

def review(con,proposal_id,decision,*,reviewer=None,rationale=None):
    decision=decision.upper()
    if decision not in ("APPROVED","REJECTED","DEFERRED"): raise ValueError(f"invalid decision {decision}")
    con.execute("""UPDATE merge_proposal SET status=?,reviewer=?,reviewed_at=?,rationale=COALESCE(?,rationale) WHERE id=?""",(decision,reviewer,now(),rationale,int(proposal_id)))
    row=con.execute("SELECT group_id FROM merge_proposal WHERE id=?",(int(proposal_id),)).fetchone()
    if row and row["group_id"]:
        gstatus="APPROVED" if decision=="APPROVED" else decision
        con.execute("UPDATE canonical_group SET status=?,updated_at=? WHERE id=?",(gstatus,now(),row["group_id"]))
    con.commit()
    return {"proposal_id":int(proposal_id),"status":decision}

def apply_proposal(con,proposal_id,*,reviewer=None):
    row=con.execute("SELECT * FROM merge_proposal WHERE id=?",(int(proposal_id),)).fetchone()
    if not row: raise ValueError("proposal not found")
    if row["status"]!="APPROVED":
        return {"applied":False,"reason":f"status is {row['status']}, not APPROVED"}
    ids=json.loads(row["item_ids"])
    canonical=ids[0]
    for iid in ids[1:]:
        con.execute("UPDATE item SET dedup_of=?,canonical_id=?,updated_at=? WHERE id=?",(canonical,canonical,now(),iid))
    con.execute("UPDATE merge_proposal SET status='APPLIED',applied_at=? WHERE id=?",(now(),int(proposal_id)))
    cg=row["group_id"]
    if cg:
        con.execute("UPDATE canonical_group SET status='APPLIED',updated_at=? WHERE id=?",(now(),cg))
    con.commit()
    return {"applied":True,"proposal_id":int(proposal_id),"canonical_item_id":canonical,"members":ids}

def mode_dispatch(con,mode,**kw):
    mode=mode.upper()
    if mode=="AUDIT": return audit(con,**{k:v for k,v in kw.items() if k in ("class_id",)})
    if mode=="PROPOSE": return propose(con,kw.get("item_ids",[]),**{k:v for k,v in kw.items() if k!="item_ids"})
    if mode=="REVIEW": return review(con,kw["proposal_id"],kw["decision"],reviewer=kw.get("reviewer"),rationale=kw.get("rationale"))
    if mode=="APPLY": return apply_proposal(con,kw["proposal_id"],reviewer=kw.get("reviewer"))
    raise ValueError(f"unknown mode {mode}")

def authoritative_filter(rows):
    out=[]
    for r in rows:
        d=r if isinstance(r,dict) else dict(r)
        if d.get("dedup_of"): continue
        out.append(r)
    return out

def is_duplicate_fp(con,class_id,hypothesis):
    fp=fingerprint({"claim":hypothesis,"class_id":class_id})
    rows=con.execute("SELECT 1 FROM dedup_fingerprint WHERE fingerprint=? LIMIT 1",(fp,)).fetchone()
    return rows is not None

def dedup_candidates(con,candidates):
    out=[]
    for c in candidates:
        cls=_item_class(c)
        q="SELECT * FROM item WHERE status='active'"; params=[]
        if cls: q+=" AND class_id=?"; params.append(cls)
        existing=con.execute(q,params).fetchall()
        matches=[]
        for e in existing:
            sim=semantic_similarity(c,dict(e),con=con,class_aware=True)
            rel=classify_relationship(c,dict(e),con=con,sim=sim)
            if rel in ("EXACT_DUPLICATE","SEMANTIC_NEAR_DUPLICATE"):
                matches.append({"item_id":e["id"],"similarity":sim,"relationship":rel})
        out.append({"candidate":c,"matches":matches,"is_duplicate":bool(matches)})
    return out

detect_exact_duplicates=find_exact_duplicates
detect_relationship=classify_relationship
create_merge_proposal=propose
approve_proposal=lambda con,pid,**kw: review(con,pid,"APPROVED",**kw)
reject_proposal=lambda con,pid,**kw: review(con,pid,"REJECTED",**kw)
defer_proposal=lambda con,pid,**kw: review(con,pid,"DEFERRED",**kw)