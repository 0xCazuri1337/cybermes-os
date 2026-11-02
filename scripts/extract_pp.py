import json, os

def extract_json_objects(text):
    start = text.find('{')
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    end = -1
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
    if end == -1:
        return None
    return text[start:end]

raw = open('research/pending/autogen-prototype_pollution.json', encoding='utf-8').read()
obj = json.loads(extract_json_objects(raw))
print("top keys:", sorted(obj.keys()))
print("n items:", len(obj.get("items", [])))

# inspect one item and its sources
it = obj["items"][0]
print("\nsample item keys:", sorted(it.keys()))
srcs = it.get("sources") or []
print("n sources:", len(srcs))
if srcs:
    print("sample source keys:", sorted(srcs[0].keys()))
    print("sample source:", srcs[0])

def source_type_for(url):
    h = url.split('/')[2] if '/' in url else ''
    if 'portswigger' in h:
        return 'primary'
    if 'github' in h:
        return 'practitioner'
    if 'owasp' in h:
        return 'primary'
    if 'mitre' in h or 'cwe' in h:
        return 'primary'
    if 'rfc-editor' in h:
        return 'standard'
    return 'practitioner'

for it in obj["items"]:
    srcs = it.get("sources") or []
    hosts = set()
    for s in srcs:
        d = s.get("domain")
        if d:
            hosts.add(d)
    print(f"{it.get('item_key','?'):45s} hosts={len(hosts)} {sorted(hosts)[:3]}")

os.remove('research/pending/autogen-prototype_pollution.json')
print("\nremoved autogen file")
