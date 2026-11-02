#!/usr/bin/env python
"""Follow the Burp MCP SSE session chain and capture any history/message events.

Strategy: connect to the SSE endpoint, read the `endpoint` event (sessionId),
then connect to `/<sessionId>`, read events, follow the chain until a
`message`/`content`/history event appears. Prints every raw line.
"""
import http.client
import time
import sys

HOST = "127.0.0.1"
PORT = 9876


def sse_connect(path="/"):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
    conn.request("GET", path, headers={"Accept": "text/event-stream"})
    resp = conn.getresponse()
    return conn, resp


def read_events(conn, resp, label, max_events=200):
    print(f"\n=== {label} ===")
    buf = ""
    count = 0
    while count < max_events:
        line = resp.readline()
        if not line:
            print("  (connection closed by server)")
            break
        line = line.decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            evt = line[len("event:"):].strip()
            print(f"  event: {evt}")
        elif line.startswith("data:"):
            data = line[len("data:"):].strip()
            print(f"  data: {data}")
            buf += data
            # handle multi-line data
            while not buf.endswith("\n") and count < max_events:
                line = resp.readline().decode("utf-8", "replace").rstrip("\r\n")
                if not line:
                    break
                buf += line
                count += 1
            if buf.strip():
                count += 1
                buf = ""
    return resp


def main():
    timeout = int(sys.argv[1]) if len(sys.argv) > 1 else 25
    t0 = time.time()
    # Connection A: root SSE -> endpoint + session A
    conn, resp = sse_connect("/")
    read_events(conn, resp, "A (root /)")

    session = None
    # Try the session-url chain a few times to find a message stream
    for hop in range(1, 8):
        # Try connecting to /?sessionId=<last-session>
        if session:
            conn, resp = sse_connect("/?sessionId=" + session)
            read_events(conn, resp, f"Bhop {hop} (/ ?sessionId={session})")
        else:
            conn, resp = sse_connect("/")
            read_events(conn, resp, "Bhop 1 (root /)")
        # Extract any sessionId from the output
        for line in resp.readlines():
            line = line.decode("utf-8", "replace").strip()
            if line.startswith("data:") and "sessionId=" in line:
                session = line.split("sessionId=", 1)[1]
                print(f"  -> captured sessionId: {session}")
        # keep-alive / re-check: re-read whatever is left
        time.sleep(0.3)

    print(f"\nElapsed: {time.time()-t0:.1f}s")
    print("No message/history events captured in", hop, "hops.")


main()
