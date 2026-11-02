"""Round-2 probe: candidate NEW publisher hosts for the wave-10 gap classes.

Wave 10 targets the measured gaps: ad_group_policy and rdp (1 item / 0 fp each),
the 2-3 item / 0 fp band (ad_trust_abuse, cache_deception, dns_enum,
segmentation_analysis, smuggling, misconfig, authn, supply_chain), and chains
for classes with chn=0.

A host is only worth shipping in a brief if it returns >=2000 chars of de-tagged
prose -- a JS shell that returns 200 proves nothing.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline, config  # noqa: E402

CITED = set("""api-security.owasp.org app.notion.com attack.mitre.org auth0.com bishopfox.com
blackhillsinfosec.com blog.cloudflare.com blog.marcfredericgomez.com blog.orange.tw
blog.qualys.com blog.sonarsource.com blog.trailofbits.com bugbountyhunter.com capec.mitre.org
cheatsheetseries.owasp.org checkmarx.com cisa.gov claroty.com cloud.google.com community.owasp.org
crowdstrike.com cvebase.io cwe.mitre.org datatracker.ietf.org detectify.com developer.mozilla.org
developer.okta.com docs.github.com docs.projectdiscovery.io elastic.co fastly.com github.blog
github.com googleprojectzero.blogspot.com hackerone.com hackertarget.com hackprosec.com
hackthrough.live helpnetsecurity.com horizon3.ai html.spec.whatwg.org httpwg.org ietf.org ired.team
kathan19.gitbook.io labs.watchtowr.com learn.microsoft.com medium.com microsoft.com mollysec.com
nccgroup.com netlas.io netlify.com okta.com oreobiscuit.gitbook.io owasp.org pentestlab.blog
portswigger.net projectdiscovery.io proofpoint.com rapid7.com raw.githubusercontent.com redcanary.com
rfc-editor.org security.googleblog.com securitylabs.datadoghq.com sedate-session-3ae.notion.site
snyk.io sonarsource.com sourcegraph.com specterops.io sploitus.com stationx.net stepsecurity.io
tailscale.com talosintelligence.com tenable.com tested-corleggy-562.notion.site thehacker.recipes
trustedsec.com ttp.parzival.sh unit42.paloaltonetworks.com vulners.com w3.org wiz.io wstg.owasp.org
zaproxy.org zscaler.com""".split())

CITED_ORGS = {config.publisher_org(h) for h in CITED}

URLS = [
    "https://dirkjan.nl/",
    "https://gtfobins.github.io/",
    "https://lolbas-project.github.io/",
    "https://sigmahq.io/",
    "https://cannalab.io/",
    "https://osint.wtf/",
    "https://www.hardbit.com/",
    "https://blog.hubspot.com/",
    "https://labs.detectify.com/",
    "https://api.msrc.microsoft.com/",
    "https://cyberattack.nl/",
    "https://www.itsec.one/",
    "https://swisskyrepo.com/",
    "https://fuzzy.re/",
    "https://evasions.checkmarx.net/",
    "https://offensivesecurityhandbook.html",
    "https://paperwhite.de/",
    "https://siege.blue/",
    "https://www.cyberbit.io/",
    "https://owasp.org/www-community/",
]

seen = set()
for u in URLS:
    host = u.split("/")[2]
    org = config.publisher_org(host)
    if org in CITED_ORGS:
        print("%-46s SKIP org=%s already cited" % (u, org))
        continue
    if host in seen:
        continue
    seen.add(host)
    try:
        r = pipeline.fetch(u)
        text = r.get("text") or ""
        st = r.get("http_status") or r.get("status")
        print("%-46s %s %6d  org=%s" % (u, st, len(text), org))
    except Exception as e:
        print("%-46s ERR %s %s" % (u, type(e).__name__, str(e)[:70]))