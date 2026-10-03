# Infrastructure & Host Service classes

**Specialization of `../` — Infrastructure.**

The services themselves, and the privileges their own configuration concedes.
These classes assume reachability and ask what the service does about it.

| Class | What it covers |
|---|---|
| [`../../infrastructure/exposed_services/knowledge/CLASS.md`](../../infrastructure/exposed_services/knowledge/CLASS.md) | administrative protocols reachable from where they should not be |
| [`../../infrastructure/exposed_rmm/knowledge/CLASS.md`](../../infrastructure/exposed_rmm/knowledge/CLASS.md) | RMM agents installed to bypass network controls |
| [`../../infrastructure/smb/knowledge/CLASS.md`](../../infrastructure/smb/knowledge/CLASS.md) | signing, null/guest sessions, named pipe coercion |
| [`../../infrastructure/winrm/knowledge/CLASS.md`](../../infrastructure/winrm/knowledge/CLASS.md) | WSMan and PowerShell remoting as movement *and* privilege |
| [`../../infrastructure/rdp/knowledge/CLASS.md`](../../infrastructure/rdp/knowledge/CLASS.md) | NLA, session hijacking, credential reuse |
| [`../../infrastructure/ldap_enum/knowledge/CLASS.md`](../../infrastructure/ldap_enum/knowledge/CLASS.md) | directory structure as extraction |
| [`../../infrastructure/dns_enum/knowledge/CLASS.md`](../../infrastructure/dns_enum/knowledge/CLASS.md) | zones that enumerate the network without touching it |
| [`../../infrastructure/service_enumeration_detail/knowledge/CLASS.md`](../../infrastructure/service_enumeration_detail/knowledge/CLASS.md) | protocol configuration as the root cause behind the rest |

Windows and Linux host-level privilege escalation belongs here when the
mechanism is host configuration rather than a network protocol.
