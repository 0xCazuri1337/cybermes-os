#!/usr/bin/env python
"""Follow the Burp MCP SSE session chain and surface message/history events."""
import http.client
import socket
import sys
import time

socket.setdefaulttimeout(1.5)
HOST = "127.0.0.1"
PORT = 9876


def connect(path):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=1.5)
    conn.request("GET", path, headers={"Accept": "text/event-stream"})
    return conn, conn.getresponse()


def read_one(resp):
    """Read a single complete SSE event (event + data)."""
    event, data = None, []
    while True:
        try:
            raw = resp.readline()
        except Exception:
            return event, "".join(data)
        if not raw:
            return event, "".join(data)
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event = line[len("event:"):].strip()
        elif line.startswith("data:"):
            data.append(line[len("data:"):].strip())
        if event is not None and data and not line.endswith("\\"):
            return event, "".join(data)
    return event, "".join(data) if event else None


def main():
    hops = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    session = None
    t0 = time.time()
    for hop in range(1, hops + 1):
        path = "/" if not session else "/?sessionId=" + session
        try:
            conn, resp = connect(path)
        except Exception as e:
            print(f"\n[hop {hop}] GET {path} -> connect error {e}")
            break
        print(f"\n[hop {hop}] GET {path}")
        found = False
        for _ in range(4):
            ev, d = read_one(resp)
            if ev is None:
                print("  (connection ended)")
                break
            print(f"  event={ev} data={d[:120]}")
            if "sessionId=" in d:
                session = d.split("sessionId=", 1)[1]
                print(f"  -> captured sessionId: {session}")
                found = True
            if "message" in ev or "content" in ev or "history" in d.lower():
                print("  *** HIT message/history event ***")
        try:
            resp.close()
        except Exception:
            pass
        time.sleep(0.2)
    print(f"\nElapsed: {time.time()-t0:.1f}s")
    print("result:", "MESSAGE/HISTORY EVENT CAPTURED" if session else "no message events found")


main()
