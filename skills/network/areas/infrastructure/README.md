# Infrastructure & Host Service classes

**Specialization of `../` — Infrastructure.**

The services themselves, and the privileges their own configuration concedes.
These classes assume reachability and ask what the service does about it.

| Class | What it covers |
|---|---|
| [`../../infrastructure/exposed_services/CLASS.md`](../../infrastructure/exposed_services/CLASS.md) | administrative protocols reachable from where they should not be |
| [`../../infrastructure/exposed_rmm/CLASS.md`](../../infrastructure/exposed_rmm/CLASS.md) | RMM agents installed to bypass network controls |
| [`../../infrastructure/smb/CLASS.md`](../../infrastructure/smb/CLASS.md) | signing, null/guest sessions, named pipe coercion |
| [`../../infrastructure/winrm/CLASS.md`](../../infrastructure/winrm/CLASS.md) | WSMan and PowerShell remoting as movement *and* privilege |
| [`../../infrastructure/rdp/CLASS.md`](../../infrastructure/rdp/CLASS.md) | NLA, session hijacking, credential reuse |
| [`../../infrastructure/ldap_enum/CLASS.md`](../../infrastructure/ldap_enum/CLASS.md) | directory structure as extraction |
| [`../../infrastructure/dns_enum/CLASS.md`](../../infrastructure/dns_enum/CLASS.md) | zones that enumerate the network without touching it |
| [`../../infrastructure/service_enumeration_detail/CLASS.md`](../../infrastructure/service_enumeration_detail/CLASS.md) | protocol configuration as the root cause behind the rest |

Windows and Linux host-level privilege escalation belongs here when the
mechanism is host configuration rather than a network protocol.
