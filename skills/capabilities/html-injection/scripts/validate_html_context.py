#!/usr/bin/env python3
"""Validate HTML injection reflection and context classification."""

import argparse
import html
import uuid
from datetime import datetime, timezone


def generate_canary(prefix: str = "CANARY") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def is_unescaped(response: str, canary: str, tag: str = "b") -> bool:
    escaped = html.escape(f"<{tag}>{canary}</{tag}>")
    raw = f"<{tag}>{canary}</{tag}>"
    return raw in response and escaped not in response


def classify_context(response: str, canary: str) -> str:
    if canary not in response:
        return "not_reflected"
    if is_unescaped(response, canary):
        return "unescaped_html"
    if html.escape(canary) in response:
        return "escaped"
    return "unknown"


def summarize(response: str, canary: str) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "canary": canary,
        "context": classify_context(response, canary),
        "unescaped": is_unescaped(response, canary),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate captured HTML injection responses (authorized testing only)"
    )
    parser.add_argument("--response-file", help="File containing a captured response")
    parser.add_argument("--canary", help="Canary to search for")
    parser.add_argument("--tag", default="b", help="Tag used in the canary")
    args = parser.parse_args()

    canary = args.canary or generate_canary()
    response = ""
    if args.response_file:
        with open(args.response_file, "r", encoding="utf-8", errors="replace") as handle:
            response = handle.read()

    result = summarize(response, canary)
    result["tag"] = args.tag
    print(result["context"])
    if result["unescaped"]:
        print(f"UNESCAPED: {canary}")


if __name__ == "__main__":
    main()
