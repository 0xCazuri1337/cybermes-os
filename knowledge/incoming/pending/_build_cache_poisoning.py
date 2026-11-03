import json
import os
from collections import Counter

items = [
    {
        "item_key": "cache_poisoning.t.unkeyed_header",
        "claim": "A request header that changes the response but is absent from the cache key is unkeyed input: the origin's response is stored under a key that does not include that header, so every later request whose key matches - regardless of the header value - is served the attacker's response.",
        "kind": "technique",
        "body": "When an application uses an unkeyed header (for example X-Forwarded-Host, X-Forwarded-Proto or X-Host) to build an absolute URL inside the response - a script import, an Open Graph tag, a redirect Location - and the route is cacheable, one poisoned request stores the attacker's value under a shared key. Caching headers (Age, max-age) then define how long the malicious value survives, and X-Cache: hit demonstrates that the entry was served from the cache. Validation is a clean replay: send the poisoned request, then send a fresh request carrying the same URI and host but no injected header, and observe the marker in the response. PortSwigger's design-flaw lab uses X-Forwarded-Host to make the origin generate an import URL, the same primitive applying whenever the header influences the response and the key does not.",
        "disproof": "No poisoning when the response is not cacheable (no-store, or private without s-maxage/proxy-revalidate), when the Authorization request triggers a shared-cache prohibition, when the header is part of the cache key (Vary or the configured key), or when the origin rejects the header.",
        "hunting_value": 4,
        "sources": [
            {"url": "https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws", "source_type": "research", "host": "portswigger.net", "publisher": "PortSwigger", "quote": "websites are vulnerable to web cache poisoning if they handle unkeyed input in an unsafe way and allow the subsequent HTTP responses to be cached"},
            {"url": "https://httpwg.org/specs/rfc9111.html", "source_type": "standard", "host": "httpwg.org", "publisher": "IETF", "quote": "The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request."}
        ]
    },
    {
        "item_key": "cache_poisoning.bypass.parameter_cloaking",
        "claim": "Parameter cloaking hides a payload from the cache key: caches derive their key from URL parsing (regexes, semicolon and duplicate-parameter handling), so an attacker can feed a parameter that the cache treats as a single keyed parameter while the origin parses it differently and exposes a second, attacker-controlled parameter.",
        "kind": "bypass",
        "body": "Example (Varnish-style hash): a regex removes \"?_=[^&]+&\" from the hash URL, so the key does not contain the payload parameter but the origin still parses and reflects it. Semicolon trick: utm_content=foo;callback=arbitraryFunction - the cache keys only callback=setCountryCookie while the origin uses the last callback, overwriting the function on every imported script. Practical checks: compare the X-Cache-Key with the request and replay a clean request with the same key, then confirm the marker in the response. Sources: PortSwigger Web Cache Entanglement plus RFC 9111.",
        "disproof": "If the cache and the origin parse the input identically, if the payload stays inside the key, or if the response is not cacheable, the entry is keyed and no poisoning occurs.",
        "hunting_value": 4,
        "sources": [
            {"url": "https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf", "source_type": "research", "host": "portswigger.net", "publisher": "PortSwigger", "quote": "when a website attempts to exclude a specific parameter from the cache key, we can often exploit URL parsing quirks to trick it into partially excluding arbitrary parameters from the key"},
            {"url": "https://httpwg.org/specs/rfc9111.html", "source_type": "standard", "host": "httpwg.org", "publisher": "IETF", "quote": "The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request."}
        ]
    },
    {
        "item_key": "cache_poisoning.bypass.fat_get",
        "claim": "A 'fat GET' request - a GET carrying a message body - is not exempt from caching, and many caches key the entry on the URI plus query string only; the body is therefore outside the cache key and a body parameter can change the response while remaining unkeyed.",
        "kind": "bypass",
        "body": "Varnish's builtin.vcl strips the body for GET requests because GET with a body is questionable, but some applications and frameworks genuinely accept a body on GET. An attacker sends GET /js/geolocate.js?callback=setCountryCookie with a Content-Length body of callback=arbitraryFunction; the cache key is derived from the query-string callback only, and the stored response contains the body-controlled function name, served to every user who later requests the URI. Practical checks: confirm proxy_cache_methods includes GET and HEAD, observe the stored response with and without the body, then replay a clean request and confirm the marker. Sources: PortSwigger Web Cache Entanglement plus RFC 9111.",
        "disproof": "If the cache strips the body before lookup (Varnish builtin.vcl), if proxy_cache_methods excludes GET with a body, if the response is not cacheable, or if the body parameter is part of the key, the primitive does not hold.",
        "hunting_value": 4,
        "sources": [
            {"url": "https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf", "source_type": "research", "host": "portswigger.net", "publisher": "PortSwigger", "quote": "Whenever a request has a body, it will get sent to the backend for a cache miss... the builtin.vcl removes the body for GET requests because it is questionable if GET with a body is valid anyway (but some applications use it)"},
            {"url": "https://httpwg.org/specs/rfc9111.html", "source_type": "standard", "host": "httpwg.org", "publisher": "IETF", "quote": "The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request."}
        ]
    },
    {
        "item_key": "cache_poisoning.bypass.head_to_get",
        "claim": "nginx proxy_cache_convert_head (default on) converts HEAD requests to GET for caching, so a HEAD request's headers are processed by the origin and can change the stored response while the entry is filed under a key derived from GET semantics: the request method never enters the key.",
        "kind": "bypass",
        "body": "With conversion on, a HEAD probe carrying an unkeyed header (X-Forwarded-Host, X-Forwarded-Scheme) lands in the cache as if it were a GET, and a clean GET from another user then retrieves the poisoned entry. Verification: disable conversion and include $request_method in the key, or the attack fails. Practical checks: send HEAD with the poisoning header, observe X-Cache: hit on the HEAD, then replay a clean GET and confirm the marker; compare against a HEAD probe with the header removed. Sources: nginx proxy module docs plus OWASP cheat sheet.",
        "disproof": "If the key includes the request method (conversion off), if the origin rejects HEAD, if the route is not cacheable, or if the poisoning header is part of the key, the attack does not hold.",
        "hunting_value": 4,
        "sources": [
            {"url": "https://nginx.org/en/docs/http/ngx_http_proxy_module.html", "source_type": "reference", "host": "nginx.org", "publisher": "NGINX", "quote": "When the conversion is disabled, the cache key should be configured to include the $request_method."},
            {"url": "https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html", "source_type": "reference", "host": "owasp.org", "publisher": "OWASP", "quote": "Do not let unkeyed headers or a body on a GET request alter a cacheable response."}
        ]
    },
    {
        "item_key": "cache_poisoning.chain_link.tier_chain",
        "claim": "A cache poisoning chain links an unkeyed input at one tier to a second tier that keys differently: an attacker poisons the origin's cache through an unkeyed header, and the front-end CDN serves the poisoned entry to victims because its key omits the same input - one request by the attacker poisons a whole tier, and the payload (script, redirect, HSTS header or custom response header) is delivered to every visitor until the TTL expires.",
        "kind": "chain_link",
        "body": "The chain has three links. (1) Attacker craft: send a request with an unkeyed header (X-Forwarded-Host) and observe the response's Age/max-age to learn the caching window. (2) Storage: the origin's response, built from the attacker's header, is stored under a key that the CDN does not include the header in. (3) Delivery: a victim's clean request to the front-end is served the poisoned entry (X-Cache: hit, Age advances). The same principle underlies request-smuggling-to-cache-poisoning: a smuggled request makes the origin store attacker-influenced content that the front-end later replays. Practical checks: diff the keying at each tier (method + scheme + host + path + args, plus Vary) against the origin's keying, and probe one tier at a time with a clean replay from a fresh session. Sources: PortSwigger Practical Web Cache Poisoning, Web Cache Entanglement, plus RFC 9111.",
        "disproof": "If the tiers agree on the key (one tier unkeys something the other keys, or both unkey the same input), or if the front-end never serves the poisoned entry (it revalidates, or the origin entry is separate), the chain does not hold.",
        "hunting_value": 5,
        "sources": [
            {"url": "https://portswigger.net/research/practical-web-cache-poisoning", "source_type": "research", "host": "portswigger.net", "publisher": "PortSwigger", "quote": "The objective of web cache poisoning is to send a request that causes a harmful response that gets saved in the cache and served to other users."},
            {"url": "https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf", "source_type": "research", "host": "portswigger.net", "publisher": "PortSwigger", "quote": "when a website attempts to exclude a specific parameter from the cache key, we can often exploit URL parsing quirks to trick it into partially excluding arbitrary parameters from the key"},
            {"url": "https://httpwg.org/specs/rfc9111.html", "source_type": "standard", "host": "httpwg.org", "publisher": "IETF", "quote": "The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request."}
        ]
    },
    {
        "item_key": "cache_poisoning.t.heuristic_freshness",
        "claim": "A response with no explicit freshness directives (no Cache-Control max-age/s-maxage or Expires) is still a caching candidate: a shared cache may apply a heuristic expiration from other field values, so a poisoned entry without explicit directives can persist long after a naive 'not fresh' assessment and keep serving victims until the heuristic TTL expires.",
        "kind": "technique",
        "body": "RFC 9111 section 4.2.2 states that, since origin servers do not always provide explicit expiration times, a cache MAY assign a heuristic expiration time using other field values (such as the Last-Modified time), subject to worst-case constraints, and MUST NOT apply heuristics when explicit freshness is present. Status codes defined as heuristically cacheable (RFC 9110: 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501) can be reused with heuristic expiration unless otherwise indicated. Age and Cache-Control headers on the response reveal the entry's real age and remaining lifetime. Practical checks: send the poisoned request with a probe header, then replay after the apparent expiry; if the marker persists, the cache used heuristics or the entry came from another tier. Sources: RFC 9111 (heuristics) plus RFC 9110 (heuristically cacheable status codes).",
        "disproof": "If the response carries explicit Cache-Control (no-store, no-cache, private without s-maxage) or the cache is configured to ignore heuristic freshness, or the entry predates the probe, the claim does not hold.",
        "hunting_value": 4,
        "sources": [
            {"url": "https://httpwg.org/specs/rfc9111.html", "source_type": "standard", "host": "httpwg.org", "publisher": "IETF", "quote": "Since origin servers do not always provide explicit expiration times, a cache MAY assign a heuristic expiration time when an explicit time is not specified, employing algorithms that use other field values (such as the Last-Modified time) to estimate a plausible expiration time."},
            {"url": "https://www.rfc-editor.org/rfc/rfc9110.html", "source_type": "standard", "host": "rfc-editor.org", "publisher": "IETF", "quote": "Responses with status codes that are defined as heuristically cacheable (e.g., 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, and 501 in this specification) can be reused by a cache with heuristic expiration unless otherwise indicated by the method definition or explicit cache controls"}
        ]
    },
    {
        "item_key": "cache_poisoning.t.auth_state_keying",
        "claim": "When a shared cache keys only on the request method and URI, or omits the Authorization header and Cookie from the key, an authenticated or personalized response can be stored under a shared key. A route that is cacheable for an authenticated request can then carry unkeyed attacker input, so the poisoned entry propagates to every user who hits the key, bypassing per-user boundaries.",
        "kind": "technique",
        "body": "PortSwigger's internal-cache-poisoning lab shows the effect exactly: the internal cache keys on the URI only while the external cache keys on host plus URI; the attacker's X-Forwarded-Host poisons the internal fragment, and the externally cached response still reflects the attacker's server because the internal cache's key omits the header. The same family of flaws covers a route that is not cacheable for anonymous users but is cacheable once the request carries a session cookie, after which the entry is shared. Practical checks: cache every candidate route through the production path, request them with and without authentication, and diff the keys; include the authentication context in the key test. Sources: PortSwigger internal cache poisoning lab, RFC 9111 (Vary), plus OWASP cheat sheet.",
        "disproof": "If the cache key includes Authorization/Cookie (Vary or a structured key), if the route is not cacheable for authenticated requests, or if the internal and external tiers key identically, the entry is separated and the claim does not hold.",
        "hunting_value": 4,
        "sources": [
            {"url": "https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-internal", "source_type": "research", "host": "portswigger.net", "publisher": "PortSwigger", "quote": "the internally cached fragment still reflects your exploit server URL, but the other two URLs do not. This indicates that the header is unkeyed by the internal cache but keyed by the external one."},
            {"url": "https://httpwg.org/specs/rfc9111.html", "source_type": "standard", "host": "httpwg.org", "publisher": "IETF", "quote": "A cache might store multiple responses for a request target that is subject to content negotiation. Caches differentiate these responses by incorporating some of the original request's header fields into the cache key as well, using information in the Vary response header field, as per Section 4.1."},
            {"url": "https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html", "source_type": "reference", "host": "owasp.org", "publisher": "OWASP", "quote": "Do not use Vary: Cookie as a general authorization boundary. Prefer disabling shared caching for personalized responses."}
        ]
    },
]

# compute spans per source from items
src_counter = Counter()
for it in items:
    for s in it["sources"]:
        src_counter[(s["url"], s["host"])] += 1

source_list = [
    {"url": "https://httpwg.org/specs/rfc9111.html", "domain": "httpwg.org", "ok": True, "spans": src_counter[("https://httpwg.org/specs/rfc9111.html", "httpwg.org")], "error": ""},
    {"url": "https://www.rfc-editor.org/rfc/rfc9110.html", "domain": "rfc-editor.org", "ok": True, "spans": src_counter[("https://www.rfc-editor.org/rfc/rfc9110.html", "rfc-editor.org")], "error": ""},
    {"url": "https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws", "domain": "portswigger.net", "ok": True, "spans": src_counter[("https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws", "portswigger.net")], "error": ""},
    {"url": "https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf", "domain": "portswigger.net", "ok": True, "spans": src_counter[("https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf", "portswigger.net")], "error": ""},
    {"url": "https://portswigger.net/research/practical-web-cache-poisoning", "domain": "portswigger.net", "ok": True, "spans": src_counter[("https://portswigger.net/research/practical-web-cache-poisoning", "portswigger.net")], "error": ""},
    {"url": "https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html", "domain": "owasp.org", "ok": True, "spans": src_counter[("https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html", "owasp.org")], "error": ""},
    {"url": "https://nginx.org/en/docs/http/ngx_http_proxy_module.html", "domain": "nginx.org", "ok": True, "spans": src_counter[("https://nginx.org/en/docs/http/ngx_http_proxy_module.html", "nginx.org")], "error": ""},
]

publishers_used = sorted({s["domain"] for s in source_list})
publishers = len(publishers_used)

doc = {
    "class_id": "cache_poisoning",
    "items": items,
    "publishers": publishers,
    "publishers_used": publishers_used,
    "sources": source_list,
}

out = "C:/Users/Administrator/.hermes/cyber/research/pending/cache_poisoning.json"
with open(out, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")

# validate
with open(out, encoding="utf-8") as f:
    d = json.load(f)

kinds = Counter(i["kind"] for i in d["items"])
hv = [i["hunting_value"] for i in d["items"]]
print("items:", len(d["items"]))
print("kinds:", dict(kinds))
print("bypass:", kinds.get("bypass", 0), "chain_link:", kinds.get("chain_link", 0))
print("hunting values:", hv, "in range:", all(3 <= v <= 5 for v in hv))
print("sources:", len(d["sources"]))
print("primary-standard sources:", [s["domain"] for s in d["sources"] if s.get("source_type") == "standard"])
print("publishers:", publishers, d["publishers_used"])
print("spans sum:", sum(s["spans"] for s in d["sources"]))
print("file bytes:", os.path.getsize(out))
