# Webshell Detection Scripts (Defensive)

These scripts are **defensive threat-hunting utilities**. They read existing logs/events and emit findings; they do not generate, deploy, or execute web shells or payloads.

- `agent.py` — Primary hunter: process-creation logs, web access logs, and file-creation events.
- `process.py` — Secondary/legacy Sysmon-focused detector (process + file events). Retained for compatibility; prefer `agent.py` for new hunts.

Safety/obsolescence notes:
- `__pycache__/` is generated Python bytecode and is not a source artifact; safe to delete/regenerate.
- No weaponized payloads are stored in this directory.
