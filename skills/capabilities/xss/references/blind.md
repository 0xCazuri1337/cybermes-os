# Blind XSS — Reference

Source provenance: `domains/web/xss/topics/blind-xss.md`.

## Technique
An injected unclosed attribute makes the browser send the rest of the response to an attacker URL, achieving data capture with no script execution (dangling markup).

## How it works
Injecting an unterminated `img src` attribute captures the rest of the victim's response into an outbound request URL, because the HTML tokenizer stays in the double-quoted attribute value state until it finds the next quotation mark.

## Kill conditions
- Application escapes/filters quote and angle brackets.
- No sensitive data follows the injection point.
- Chrome blocks img URLs containing raw angle brackets/newlines.
- CSP `img-src 'self'` blocks external request.

## Validation
- Confirm OOB callback received with captured data.
- Confirm no script execution required for impact.

## OOB-Or-It-Didn't-Happen Gate (Blind / Stored XSS)

For blind and stored XSS, claims require out-of-band confirmation, same as blind SSRF. The OOB receiver fires when the payload actually executes in a browser somewhere (admin reviewing logs, SOC analyst opening a ticket, email rendering a stored payload).

### What is NOT confirmation

- ASP.NET request validator rejected `<` and returned a different status code -> WAF noise.
- Payload appears in response body URL-encoded or HTML-encoded -> correct output encoding.
- Form action contains payload string as `%22onclick%3D…` -> browser does NOT decode URL encoding inside HTML attribute values.
- `<script>` appears as `&lt;script&gt;` -> escaping.

### What IS confirmation

- A request to your unique Collaborator subdomain (e.g., `bxss-err-<random>.<collab>.oastify.com`) arrives in the OOB listener after payload was stored/reflected/queued.
- For stored XSS: request may arrive hours/days later when an admin views the resource. Plant payloads early and keep listener open.
- User-Agent of firing request is a browser (Mozilla/Chrome), not the server's own backend HTTP client.

### Where to plant blind-XSS beacons

Any field whose value might be viewed in an admin UI/log viewer/email/report later:
- Error messages, auth-flow source params (`?Source=`, `?ReturnUrl=`), login form username (audit logs), User-Agent header, Referer header, email addresses on registration/contact forms, file-upload filenames.

Always sub-tag the Collaborator subdomain by sink so callbacks identify which field fired.
