# Methodology — XSS (Cross-Site Scripting)

> Generated 2026-10-01T18:41:23Z. Competency id: `xss`.
> Aligned with `CONTROL/CONTROL.md` §4 (separation of claims) and
> `CONTROL/rules.md` R2 (scanner output is an observation, not proof).

## What this establishes

Determining whether attacker-controlled input reaches an execution sink, in which context, and whether the browser will execute it there. Context determines everything.

## Procedure

 1. **Find the source** — Every parameter, header, path segment, stored field, and postMessage origin that
reflects or is later rendered.
 2. **Find the sink** — innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, new Function,
setTimeout(string), jQuery .html(), template interpolation, and framework bindings.
 3. **Determine the context** — HTML body, HTML attribute, JavaScript string, JavaScript code, URL, CSS, JSON parsed as
HTML, or a template. The correct payload is entirely determined by this.
 4. **Determine the framework** — Angular, React, Vue, and templating engines escape differently from each other and from
raw DOM APIs. Framework-specific sinks do not behave like plain HTML.
 5. **Understand the encoding applied** — Where in the pipeline encoding happens, and whether it is context-correct. Most missed
XSS is a context mismatch, not a bypass.
 6. **Build a context-correct probe** — Minimal, non-destructive, and identifiable. Attribute it so it can be cleaned up.
 7. **Confirm execution** — Not 'the payload appears' — that is reflection. Execution means the browser ran it.
 8. **Establish impact** — Cookie access depends on HttpOnly; the real impact is often session riding, DOM read, or
privileged action. State which.
 9. **Check the stored variant separately** — Stored XSS has a different blast radius and a different reporter, and often a higher
severity.
10. **Sanitise after testing** — You have written to their application. Record exactly what you wrote so it can be
removed.

## What would disprove the hypothesis

A finding here is wrong if any of the following holds. Check them before
reporting, and record which one applied.

- The value is encoded for the exact context it lands in.
- Reflection occurs in a non-executable context (HTML comment, plain text).
- The framework's binding escapes by construction and no raw sink is reached.

## Gates before this becomes a finding

- execution confirmed in the browser, not inferred
- context identified and encoding understood
- impact named specifically, not 'XSS'

## Authority

`CONTROL/CONTROL.md` outranks this page. If this procedure suggests an action
outside the recorded scope, the scope wins — see `CONTROL/state.md`.

Tools are sensors. A tool that reports a finding here has satisfied none of
the gates above by itself.
