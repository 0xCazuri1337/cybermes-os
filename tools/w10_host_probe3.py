"""Round-3 probe: targeted NEW hosts for the wave-10 gap classes.

Round 2 found: dirkjan.nl, github.io (gtfobins/lolbas), sigmahq.io,
cyberattack.nl as usable. This round looks specifically for publishers with real
prose on the two weakest classes (ad_group_policy, rdp) and the 0-fp band
(cache_deception, smuggling, dns_enum, segmentation_analysis, supply_chain).

Rejects any host whose publisher_org is already cited, and any page under 2000
chars of de-tagged prose.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline, config  # noqa: E402

CITED_ORGS = {config.publisher_org(h) for h in """api-security.owasp.org app.notion.com
attack.mitre.org auth0.com bishopfox.com blackhillsinfosec.com blog.cloudflare.com
blog.marcfredericgomez.com blog.orange.tw blog.qualys.com blog.sonarsource.com
blog.trailofbits.com bugbountyhunter.com capec.mitre.org cheatsheetseries.owasp.org checkmarx.com
cisa.gov claroty.com cloud.google.com community.owasp.org crowdstrike.com cvebase.io cwe.mitre.org
datatracker.ietf.org detectify.com developer.mozilla.org developer.okta.com docs.github.com
docs.projectdiscovery.io elastic.co fastly.com github.blog github.com
googleprojectzero.blogspot.com hackerone.com hackertarget.com hackprosec.com hackthrough.live
helpnetsecurity.com horizon3.ai html.spec.whatwg.org httpwg.org ietf.org ired.team
kathan19.gitbook.io labs.watchtowr.com learn.microsoft.com medium.com microsoft.com mollysec.com
nccgroup.com netlas.io netlify.com okta.com oreobiscuit.gitbook.io owasp.org pentestlab.blog
portswigger.net projectdiscovery.io proofpoint.com rapid7.com raw.githubusercontent.com
redcanary.com rfc-editor.org security.googleblog.com securitylabs.datadoghq.com
sedate-session-3ae.notion.site snyk.io sonarsource.com sourcegraph.com specterops.io sploitus.com
stationx.net stepsecurity.io tailscale.com talosintelligence.com tenable.com
tested-corleggy-562.notion.site thehacker.recipes trustedsec.com ttp.parzival.sh
unit42.paloaltonetworks.com vulners.com w3.org wiz.io wstg.owasp.org zaproxy.org zscaler.com""".split()}

URLS = [
    "https://dirkjan.nl/",
    "https://gtfobins.github.io/",
    "https://lolbas-project.github.io/",
    "https://sigmahq.io/",
    "https://cyberattack.nl/",
    "https://hackmd.io/",
    "https://infosecwriteups.com/",
    "https://github.com/OTRF/Set-AuditRule",
    "https://www.hackplayers.org/",
    "https://labs.ripe.net/",
    "https://whoogle.no/",
    "https://blog.securityinnovation.com/",
    "https://www.securityauthentication.com/",
    "https://trustedsec.com/",
    "https://adsecurity.mit.edu/",
    "https://github.com/leechristensen/registry-dump/",
    "https://godot.engine.org/",
    "https://0xdamage.gitbook.io/",
    "https://book.hacktricks.wiki/",
    "https://cyberchef.org/",
    "https://www.hackthebox.com/",
    "https://academy.hackthebox.com/",
    "https://enigmatic.notion.site/",
    "https://slayer.gitbook.io/",
    "https://ninocraft.gitbook.io/",
    "https://s3.amazonaws.com/",
]

seen = set()
for u in URLS:
    host = u.split("/")[2]
    org = config.publisher_org(host)
    if org in CITED_ORGS:
        print("%-52s SKIP org=%s" % (u, org))
        continue
    if host in seen:
        continue
    seen.add(host)
    try:
        r = pipeline.fetch(u)
        text = r.get("text") or ""
        st = r.get("http_status") or r.get("status")
        print("%-52s %s %6d  org=%s" % (u, st, len(text), org))
    except Exception as e:
        print("%-52s ERR %s %s" % (u, type(e).__name__, str(e)[:60]))