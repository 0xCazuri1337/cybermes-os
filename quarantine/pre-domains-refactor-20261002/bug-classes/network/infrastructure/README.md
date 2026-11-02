# Infrastructure & Host Service classes

**Specialization of `../` — Infrastructure.**

The services themselves, and the privileges their own configuration concedes.
These classes assume reachability and ask what the service does about it.

| Class | What it covers |
|---|---|
| [`exposed-services.md`](exposed-services.md) | administrative protocols reachable from where they should not be |
| [`exposed-rmm.md`](exposed-rmm.md) | RMM agents installed to bypass network controls |
| [`smb.md`](smb.md) | signing, null/guest sessions, named pipe coercion |
| [`winrm.md`](winrm.md) | WSMan and PowerShell remoting as movement *and* privilege |
| [`rdp.md`](rdp.md) | NLA, session hijacking, credential reuse |
| [`ldap-enumeration.md`](ldap-enumeration.md) | directory structure as extraction |
| [`dns-enumeration.md`](dns-enumeration.md) | zones that enumerate the network without touching it |
| [`service-configuration.md`](service-configuration.md) | protocol configuration as the root cause behind the rest |

Windows and Linux host-level privilege escalation belongs here when the
mechanism is host configuration rather than a network protocol.
