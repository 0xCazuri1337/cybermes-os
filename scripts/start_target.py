"""Bootstrap a new target folder under Projects/<slug>."""
import sys, os, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TPL = os.path.join(ROOT, "templates")
PROJ = os.path.join(ROOT, "Projects")

def main():
    if len(sys.argv) < 2:
        print("usage: python scripts/start_target.py <slug>")
        sys.exit(1)
    slug = sys.argv[1]
    base = os.path.join(PROJ, slug)
    if os.path.exists(base):
        print(f"exists: {base}")
        sys.exit(1)
    os.makedirs(base)
    for sub in ("notes", "leads", "primitives", "findings", "reports", "recon"):
        os.makedirs(os.path.join(base, sub))
    os.makedirs(os.path.join(base, ".claude"))
    # target CLAUDE.md from template
    src = os.path.join(TPL, "target-claude.md")
    dst = os.path.join(base, ".claude", "CLAUDE.md")
    if os.path.exists(src):
        shutil.copyfile(src, dst)
    # scope/creds stubs
    with open(os.path.join(base, "scope.md"), "w") as f:
        f.write("# Scope\n\n- In scope: \n- Out of scope: \n")
    with open(os.path.join(base, "creds.md"), "w") as f:
        f.write("# Creds\n\nSee E:/bugbounty/_shared/creds.txt\n")
    print(f"created {base}")

if __name__ == "__main__":
    main()
