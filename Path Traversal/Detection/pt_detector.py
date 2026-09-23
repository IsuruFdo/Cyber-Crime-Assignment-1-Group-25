#!/usr/bin/env python3
import posixpath
import re
import sys
from urllib.parse import unquote

LOG_PATTERN = re.compile(
    r'^(?P<client>\S+) - - \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<target>\S+) HTTP/[\d.]+" (?P<status>\d{3})'
)
ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
DOCUMENT_ROOT = "/app_files"
COLORS = {"CRIT": "\033[91m", "WARN": "\033[93m"}
RESET = "\033[0m"


def deep_decode(value):
    for _ in range(4):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def is_traversal_pattern(value):
    return (
        ".." in value
        or value.startswith(("/", "\\"))
        or re.match(r"^[A-Za-z]:", value) is not None
        or "\x00" in value
    )


def escapes_root(value):
    resolved = posixpath.normpath(posixpath.join(DOCUMENT_ROOT, value.replace("\\", "/")))
    return not (resolved == DOCUMENT_ROOT or resolved.startswith(DOCUMENT_ROOT + "/"))


def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 pt_detector.py <access.log | ->")
    source = sys.argv[1]
    color = sys.stdout.isatty()

    total = 0
    file_requests = 0
    successes = []
    attempts = []

    def log_alert(level, code, ts, client, method, raw, decoded, note):
        param = f"file={raw}" + (f" (decoded: {decoded})" if decoded != raw else "")
        line = f"{ts}  [{level}] {code:<17} {client} {method} {param} -> {note}"
        print(f"{COLORS[level]}{line}{RESET}" if color else line, flush=True)

    print(f"[detector] Processing: {'stdin (live)' if source == '-' else source}", flush=True)
    stream = sys.stdin if source == "-" else open(source, encoding="utf-8", errors="replace")
    try:
        for line in stream:
            match = LOG_PATTERN.match(ANSI_PATTERN.sub("", line))
            if not match:
                continue
            total += 1
            path, _, query = match["target"].partition("?")
            file_match = re.search(r"(?:^|&)file=([^&]*)", query)
            if not file_match:
                continue
            file_requests += 1
            raw = file_match.group(1)
            decoded = deep_decode(raw)
            if not is_traversal_pattern(decoded):
                continue
            status = int(match["status"])
            alert_args = (match["ts"], match["client"], match["method"], raw, decoded)
            if escapes_root(decoded) and status == 200:
                successes.append(decoded)
                log_alert("CRIT", "TRAVERSAL_SUCCESS", *alert_args,
                            "Escapes document boundary and returned HTTP 200 (data leaked)")
            else:
                attempts.append(decoded)
                reason = ("Escapes document boundary but blocked/unresolved"
                            if escapes_root(decoded) else "Contains traversal sequence, remains within root")
                log_alert("WARN", "TRAVERSAL_ATTEMPT", *alert_args, f"{reason} (HTTP {status})")
    except KeyboardInterrupt:
        print()
    finally:
        if stream is not sys.stdin:
            stream.close()

    if successes:
        label, code, meaning = "COMPROMISED", 1, "Files outside boundary were served successfully."
    elif attempts:
        label, code, meaning = "SUSPICIOUS", 2, "Traversal attempts observed, but no data leaked."
    else:
        label, code, meaning = "CLEAN", 0, "No path traversal attempts detected."

    bar = "=" * 64
    print(f"\n{bar}\n PATH TRAVERSAL - DETECTION SUMMARY\n{bar}")
    print(f" Requests analysed          : {total}")
    print(f" File endpoint requests     : {file_requests}")
    print(f" Traversal payloads detected: {len(successes) + len(attempts)} "
        f"({len(successes)} succeeded, {len(attempts)} failed)")
    if successes:
        print(f" Compromised paths          : {', '.join(sorted(set(successes)))}")
    print(bar)
    print(f" VERDICT: {label}  (exit code {code})")
    print(f" {meaning}\n{bar}")
    return code


if __name__ == "__main__":
    sys.exit(main())