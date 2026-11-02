# API Reference: SSTI Detection Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for sending template injection payloads |

## CLI Usage

```bash
python scripts/agent.py --url "https://target.com/page" --param name --method GET --output ssti.json
```

## Functions

### `test_ssti_detection(url, param, method, headers) -> list`
Tests 7 engine-specific payloads (`{{7*7}}`, `${7*7}`, etc.) and checks if `49` appears in the response (context-aware, baseline-compared).

### `identify_engine(url, param, method, headers) -> dict`
Differentiates engines: `{{7*'7'}}` returning `7777777` = Jinja2, `49` = Twig. Also tests Freemarker (`${.now}`) and Velocity.

### `test_jinja2_rce(url, param, method, headers) -> list`
Tests `cycler.__init__.__globals__.os.popen`, `lipsum.__globals__`, and `config.SECRET_KEY` disclosure.

### `test_twig_rce(url, param, method, headers) -> list`
Tests `filter('system')` and `file_excerpt` payloads.

### `test_freemarker_rce(url, param, method, headers) -> list`
Tests `freemarker.template.utility.Execute` for Java command execution.

### `test_blind_ssti(url, param, method, headers) -> list`
Blind SSTI via time-based oracles comparing against a baseline request.

### `test_mako_rce(url, param, method, headers) -> list`
Tests Mako (Python) RCE payloads.

### `validate_rce_marker(url, param, method, headers, marker) -> dict`
Safe RCE validation using a harmless echo marker.

### `run_assessment(url, param, method) -> dict`
Runs detection, identifies engine, then tests engine-specific RCE payloads.

## Detection Payloads

| Engine | Payload | Expected |
|--------|---------|----------|
| Jinja2/Twig | `{{7*7}}` | `49` |
| Freemarker | `${7*7}` | `49` |
| ERB/EJS | `<%= 7*7 %>` | `49` |
| Smarty | `{7*7}` | `49` |
| Velocity | `#set($x=7*7)$x` | `49` |

## Output Schema

```json
{
  "target": "https://target.com/page",
  "parameter": "name",
  "vulnerable": true,
  "engine": {"engine": "Jinja2", "language": "Python"},
  "rce_tests": [{"name": "cycler_popen", "rce_confirmed": true}]
}
```
