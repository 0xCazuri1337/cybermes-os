"""Register the 3 classes the field evidence actually needs, then verify routing.

Only three are new, because most patterns map onto classes that already exist:
mass_assign (23 items) already exists, and version disclosure belongs to
info_disclosure. Registering a class per pattern would have invented taxonomy to
hold my own findings -- the failure mode the corpus exists to prevent.

  eol_software  a version/end-of-life platform that can never be patched. Distinct
                from info_disclosure because the defect is the unpatchability, not
                the disclosure: the reported CVE was tested and was NOT exploitable,
                and the finding survived anyway on reachability.
  rate_limit    absence of throttling, where the operation happens is the whole
                question -- and where "no throttling observed" is usually a thin
                test rather than a finding.
  otp           one-time-password endpoints, where the common trap is an endpoint
                that responds identically to an invalid number (a stub) or returns
                a token that does not vary per user (a session nonce).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import domains, store  # noqa: E402

NEW = [
    # (class_id, domain, surface, title, one-line purpose)
    ("eol_software", "web", "infra",
     "End-of-life and unpatchable platform",
     "A platform or version past end of life that receives no fixes, on an "
     "internet-reachable surface. Distinct from version disclosure: the defect "
     "is that no future fix is possible."),
    ("rate_limit", "web", "identity",
     "Rate limiting and throttling",
     "Missing or ineffective throttling on a security-relevant operation, "
     "including the cases where the operation is not reachable at all."),
    ("otp", "web", "identity",
     "One-time password endpoints",
     "OTP issuance, verification, and the stubs and nonces that look like "
     "issuance without being it."),
]


def main():
    con = store.connect()
    con.execute("PRAGMA busy_timeout=20000")
    have = {r[0] for r in con.execute("SELECT id FROM bug_class")}
    for cid, dom, surf, title, purpose in NEW:
        if cid not in have:
            # TWO schema facts found the hard way, both of which made this write
            # nothing while exiting 0:
            #   1. the column is `name`, not `title`;
            #   2. `first_seen` is NOT NULL.
            # `INSERT OR IGNORE` swallowed the NOT NULL violation as a constraint
            # failure, so total_changes stayed 0 and the row was never written --
            # a silent no-op that still prints "registered". Plain INSERT, all
            # NOT NULL columns, so a constraint breach is loud.
            con.execute(
                "INSERT INTO bug_class (id, name, surface, summary, first_seen)"
                " VALUES (?,?,?,?,date('now'))", (cid, title, surf, purpose))
            print("registered bug_class: %s (changes=%d)"
                  % (cid, con.execute(
                      "SELECT COUNT(*) FROM bug_class WHERE id=?",
                      (cid,)).fetchone()[0]))
        d = domains.domain_of(con, cid)
        if d != dom:
            con.execute("INSERT OR REPLACE INTO class_domain (class_id, domain)"
                        " VALUES (?,?)", (cid, dom))
            print("  routed %s -> %s" % (cid, dom))
    con.commit()

    # VERIFY by reading back through the same API the tree check uses. Writing a
    # row is not evidence the route resolves; the earlier reorg shipped 22
    # classes with no class_domain row precisely because nothing read it back.
    bad = []
    for cid, dom, _s, _t, _p in NEW:
        got = domains.domain_of(con, cid)
        if got != dom:
            bad.append("%s: expected %s, class_domain says %r" % (cid, dom, got))
    n = con.execute("SELECT COUNT(*) FROM class_domain").fetchone()[0]
    m = con.execute("SELECT COUNT(*) FROM bug_class").fetchone()[0]
    print("class_domain rows=%d  bug_class rows=%d" % (n, m))
    if bad:
        raise SystemExit("ROUTING FAILED:\n  " + "\n  ".join(bad))
    print("ASSERT OK: all 3 resolve through domains.class_domain()")


if __name__ == "__main__":
    main()