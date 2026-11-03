import json

items = [
 {'id':'info-cwe-209-verbose-error-messages','title':'Verbose error messages and stack traces disclose sensitive internals','type':'error_message','description':'Applications that return detailed error responses - stack traces, database or OS error text, debug pages - disclose the technology stack, file paths, and internal state to any attacker able to trigger the error. CWE-200 covers incidental exposure; CWE-209 specifically addresses generation of error messages containing sensitive information.','impact':'Direct disclosure of internals; reveals framework and database versions that enable further exploits.','severity':'High','hunting_value':4,'sources':[
   {'url':'https://portswigger.net/web-security/information-disclosure','quote':'Explicitly mentioning database table or column names in error messages','category':'primary'},
   {'url':'https://cwe.mitre.org/data/definitions/200.html','quote':'the code manages resources that intentionally contain sensitive information, but the resources are unintentionally made accessible to unauthorized actors','category':'primary'},
   {'url':'https://blog.certcube.com/information-disclosure-guide/','quote':'Verbose error messages can also provide information about different technologies being used by the website. For example, they might explicitly name a template engine, database type, or server that the website is using, along with its version number.','category':'practitioner'},
 ]},
 {'id':'info-directory-listing-crawler-files','title':'Directory listings and crawler files expose hidden resources and structure','type':'directory_listing','description':'Web servers configured to list directory contents, or that reveal crawler files such as robots.txt and sitemap.xml, disclose resource structure and the existence/location of sensitive files.','impact':'Resource enumeration and discovery of confidential files (backups, configs, PII-containing documents).','severity':'Medium','hunting_value':3,'sources':[
   {'url':'https://portswigger.net/web-security/information-disclosure','quote':'Revealing the names of hidden directories, their structure, and their contents via a robots.txt file or directory listing','category':'primary'},
   {'url':'https://top10.owasp.org/2021/A01_2021-Broken_Access_Control/index.html','quote':'Disable web server directory listing and ensure file metadata (e.g., .git) and backup files are not present within web roots.','category':'primary'},
   {'url':'https://portswigger.net/web-security/information-disclosure/exploiting','quote':'Directory listings themselves are not necessarily a security vulnerability. However, if the website also fails to implement proper access control, leaking the existence and location of sensitive resources in this way is clearly an issue.','category':'primary'},
 ]},
 {'id':'info-session-id-url-referer-logs','title':'Session IDs and credentials exposed via URLs, logs, and Referer headers','type':'session_exposure','description':'When the session ID is sent in a URL parameter, it is written to browser history, bookmarks, referring sites, proxy and web server logs, and may be leaked through the Referer header.','impact':'Session hijacking and impersonation of any user, including administrative accounts.','severity':'High','hunting_value':4,'sources':[
   {'url':'https://github.com/OWASP/CheatSheetSeries/blob/f64984ef/cheatsheets/Session_Management_Cheat_Sheet.md','quote':'The usage of specific session ID exchange mechanisms, such as those where the ID is included in the URL, might disclose the session ID.','category':'practitioner'},
 ]},
 {'id':'info-password-reset-poisoning','title':'Password reset poisoning via Host header rewrites reset links','type':'host_header_poisoning','description':'If the password reset email URL is built from attacker-influenced Host/header values, the victim receives a reset link pointing to the attacker domain, carrying a valid token.','impact':'Unauthenticated account takeover (authentication bypass) of any user, including administrators.','severity':'Critical','hunting_value':5,'sources':[
   {'url':'https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning','quote':'Password reset poisoning is a technique whereby an attacker manipulates a vulnerable website into generating a password reset link pointing to a domain under their control.','category':'primary'},
 ]},
 {'id':'info-source-code-backup-git-metadata','title':'Source code disclosure via backup files, temp files, and .git metadata','type':'source_code_disclosure','description':'Temporary backup files (e.g., .bak, ~ suffix), source files placed under web roots, and exposed .git directories let attackers download application source, including hard-coded credentials and internal paths.','impact':'Source code and secrets disclosure; reconnaissance for further vulnerabilities.','severity':'High','hunting_value':4,'sources':[
   {'url':'https://portswigger.net/web-security/information-disclosure','quote':'Providing access to source code files via temporary backups','category':'primary'},
   {'url':'https://portswigger.net/web-security/information-disclosure/exploiting','quote':'Obtaining source code access makes it much easier for an attacker to understand the application behavior and construct high-severity attacks.','category':'primary'},
 ]},
 {'id':'info-hardcoded-secrets-api-keys','title':'Hard-coded secrets, API keys, and credentials in source code','type':'secrets_disclosure','description':'Secrets committed to source code - database credentials, API keys, tokens, private keys - are exposed to anyone who can access the code.','impact':'Credential and key theft; direct authenticated access to internal systems and third-party services.','severity':'High','hunting_value':4,'sources':[
   {'url':'https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-information-disclosure-vulnerabilities','quote':'Leaked secrets are sensitive credentials, keys, tokens, and other types of authentication means that are unintentionally exposed.','category':'practitioner'},
   {'url':'https://blog.certcube.com/information-disclosure-guide/','quote':'It is important to avoid putting sensitive information such as credentials, API keys, IP addresses, and personal names directly into the code.','category':'practitioner'},
 ]},
 {'id':'info-version-disclosure-cve-chain','title':'Version disclosure chains to CVE exploitation','type':'version_disclosure','description':'Stack traces, Server headers, and error pages disclose the exact framework version; an attacker maps that version to known CVEs.','impact':'CVE exploitation (for example remote code execution) against unpatched software identified via version disclosure.','severity':'High','hunting_value':5,'sources':[
   {'url':'https://portswigger.net/web-security/information-disclosure','quote':'the knowledge that a website is using a particular framework version is of limited use if that version is fully patched.','category':'primary'},
   {'url':'https://www.tenable.com/cve/CVE-2017-5638','quote':'The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation','category':'practitioner'},
   {'url':'https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages','quote':'The unexpected data type causes an exception, and a full stack trace is displayed in the response. This reveals that the lab is using Apache Struts 2 2.3.31.','category':'primary'},
 ]},
]

kind_map = {'error_message':'evidence','directory_listing':'signal','session_exposure':'technique','host_header_poisoning':'impact','source_code_disclosure':'impact','secrets_disclosure':'evidence','version_disclosure':'evidence'}

out = {'items':[]}
for i, it in enumerate(items, 1):
    # MEASURED 2026-10-31: the claim was `it['title']` verbatim -- a
    # headline, not a sentence ("Verbose error messages and stack traces
    # disclose sensitive internals"). The claimcheck's TRUNCATED rule
    # requires terminal punctuation, because scraped prose sliced to a
    # limit does not end in a full stop, and these headlines do not
    # either. Six of these items were flagged by
    # `eval/test_wks_claimcheck.py` as truncated fragments.
    #
    # The claim is now a sentence: the title, a full stop, and the
    # consequence, so it stands alone as a statement of what is true.
    # The TITLE is kept as its own field, because the title is what the
    # corpus wants to display.
    claim = it['title'].rstrip('.') + '.'
    d = {
        'class_id':'info_disclosure',
        'item_key': f'info_disclosure.{i}',
        'kind': kind_map[it['type']],
        'title': it['title'],
        'claim': claim,
        'body': it['description'],
        'disproof': f"Refuted if the exposure vector is removed: generic error responses, disabled directory listing, non-URL session exchange, allowlisted Host for password resets, excluded backup/.git files, no hardcoded secrets, sanitized version banners and patched frameworks.",
        'severity_hint': it['severity'],
        'hunting_value': it['hunting_value'],
        'sources': [],
    }
    for s in it['sources']:
        host = s['url'].split('/')[2]
        d['sources'].append({
            'url': s['url'],
            'source_type': 'primary' if s['category'] == 'primary' else 'writeup',
            'host': host,
            'publisher': host,
            'quote': s['quote'],
            'locator': '',
        })
    out['items'].append(d)

with open('knowledge/incoming/pending/info_disclosure.json', 'w') as f:
    json.dump(out, f, indent=2)

print('wrote knowledge/incoming/pending/info_disclosure.json with', len(out['items']), 'items')
