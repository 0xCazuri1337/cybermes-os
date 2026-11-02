# Detection and Tooling

## Automated
- ppfuzz: `ppfuzz -l urls.txt -o results.txt`
- Nuclei: `echo URL | nuclei -t http/vulnerabilities/generic/prototype-pollution.yaml`
- Burp Scanner: Server-side prototype pollution check; DOM Invader client-side.
- pp-finder: `npx pp-finder /path/to/node_modules/package`

## Manual
- Status-code reflection, JSON spacing, toString null crash.
- Source code review for unsafe merge/clone/extend and missing __proto__/constructor/prototype filtering.

## Remediation
- Use Object.create(null) / Map for user data.
- Freeze Object.prototype.
- Reject __proto__, constructor, prototype keys in merges.
- Update vulnerable libraries (lodash >= 4.17.12).
