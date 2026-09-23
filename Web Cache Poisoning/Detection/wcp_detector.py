#!/usr/bin/env python3
import argparse
import json
import os
import signal
import sys
import time
from datetime import datetime

COLORS = {"CRIT": "\033[91m", "WARN": "\033[93m", "INFO": "\033[96m"}
RESET = "\033[0m"


def parse_ts(ts):
    try:
        return datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None


class Analyzer:
    def __init__(self, trusted=()):
        self.trusted = {h.strip().lower() for h in trusted}
        self.total = 0
        self.bad_lines = 0
        self.spoofs = []
        self.poison_writes = []
        self.poisoned_hits = []
        self.victim_hits = []
        self.open_windows = {}
        self.windows = []

    def _foreign(self, host, real):
        h = host.strip().lower()
        return h != (real or "").strip().lower() and h not in self.trusted

    def feed(self, rec):
        self.total += 1
        alerts = []
        ts = rec.get("ts")
        path = rec.get("path")
        real = rec.get("host") or ""
        xfh = rec.get("x_forwarded_host")
        served = rec.get("served_host")
        cache = rec.get("cache_status")
        client = rec.get("client")

        # Close active poison tracking if cache was reset
        if path == "/clear-cache":
            if self.open_windows:
                for w in self.open_windows.values():
                    w["closed"] = ts
                alerts.append((ts, "INFO", "CACHE_CLEARED",
                               "Cache cleared - active poison window closed"))
                self.open_windows = {}
            return alerts

        spoofed = bool(xfh) and self._foreign(xfh, real)

        # 1. Check for untrusted header injection
        if spoofed:
            self.spoofs.append(rec)
            alerts.append((ts, "WARN", "SPOOF_HEADER",
                           f"{client} sent X-Forwarded-Host: {xfh} (Host: {real}) on {rec.get('method')} {path}"))

            # 2. Check if spoofed host was cached on MISS
            if cache == "MISS" and served and served.strip().lower() == xfh.strip().lower():
                window = {"path": path, "host": xfh, "opened": ts, "closed": None,
                          "attacker": client, "hits": []}
                self.open_windows[path] = window
                self.windows.append(window)
                self.poison_writes.append(rec)
                alerts.append((ts, "CRIT", "POISON_WRITE",
                               f"'{xfh}' reflected into response for {path} and cached"))

        # 3. Check for cache HIT serving poisoned content
        if cache == "HIT" and served and self._foreign(served, real):
            self.poisoned_hits.append(rec)
            window = self.open_windows.get(path)
            if window and served.strip().lower() == window["host"].strip().lower():
                note = f"(window opened at {window['opened'][11:23]})"
            else:
                note = ""
                window = None

            who = "Attacker re-read own entry" if spoofed else "VICTIM served attacker content"
            if not spoofed:
                self.victim_hits.append(rec)
                if window:
                    window["hits"].append(rec)

            alerts.append((ts, "CRIT", "POISONED_HIT",
                           f"{who}: {client} received cached host '{served}' instead of '{real}' {note}".strip()))
        return alerts

    def verdict(self):
        if self.poisoned_hits:
            return ("COMPROMISED", 1, "Poisoned cache entries were served to clients.")
        if self.spoofs:
            return ("SUSPICIOUS", 2, "Spoofed headers observed, but no poisoned responses served.")
        return ("CLEAN", 0, "No anomalous headers or poisoned cache entries observed.")


def emit(alert, color):
    ts, level, code, msg = alert
    stamp = ts[11:23] if ts and len(ts) >= 23 else (ts or "")
    line = f"{stamp}  {'[' + level + ']':<6} {code:<13} {msg}"
    print(f"{COLORS[level]}{line}{RESET}" if color else line, flush=True)


def handle_line(line, an, color):
    line = line.strip()
    if not line:
        return
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        an.bad_lines += 1
        return
    for alert in an.feed(rec):
        emit(alert, color)


def summarize(an, log_path, color):
    label, code, meaning = an.verdict()
    bar = "=" * 64
    print(f"\n{bar}\n WEB CACHE POISONING - DETECTION SUMMARY\n{bar}")
    print(f" Log file                    : {log_path}")
    print(f" Requests analysed           : {an.total}" + (f"  ({an.bad_lines} malformed lines skipped)" if an.bad_lines else ""))
    print(f" Spoofed-header requests     : {len(an.spoofs)}")
    print(f" Poison writes               : {len(an.poison_writes)}")
    print(f" Poisoned cache hits served  : {len(an.poisoned_hits)}  (victims: {len(an.victim_hits)})")
    hosts = sorted({r['x_forwarded_host'] for r in an.spoofs})
    if hosts:
        print(f" Attacker-controlled host(s) : {', '.join(hosts)}")
    for w in an.windows:
        first = parse_ts(w["hits"][0]["ts"]) if w["hits"] else None
        opened = parse_ts(w["opened"])
        delta = f", first victim after {int((first - opened).total_seconds() * 1000)} ms" if first and opened else ""
        state = f"closed at {w['closed'][11:23]}" if w["closed"] else "active in cache"
        print(f" Poison window ({w['path']})  : opened {w['opened'][11:23]}, "
              f"{len(w['hits'])} victim request(s) served{delta}, {state}")
    if an.poison_writes and an.poisoned_hits:
        print(f" Blast radius                : {len(an.poison_writes)} attacker request(s) -> "
              f"{len(an.victim_hits)} victim response(s) poisoned")
    print(bar)
    text = f" VERDICT: {label}  (exit code {code})"
    level = {"COMPROMISED": "CRIT", "SUSPICIOUS": "WARN", "CLEAN": "INFO"}[label]
    print(f"{COLORS[level]}{text}{RESET}" if color else text)
    print(f" {meaning}\n{bar}")
    return code


def main():
    ap = argparse.ArgumentParser(description="Web Cache Poisoning detector and log analyser")
    ap.add_argument("logfile", help="JSON log file path")
    ap.add_argument("--follow", action="store_true", help="Live stream mode")
    ap.add_argument("--trusted-host", action="append", default=[],
                    help="Whitelisted host for reverse proxies")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()
    color = sys.stdout.isatty() and not args.no_color
    an = Analyzer(args.trusted_host)

    print(f"[detector] monitoring {args.logfile}" + (" (live mode)" if args.follow else ""))
    if args.follow:
        stop = {"now": False}

        def _stop(signum, frame):
            stop["now"] = True

        signal.signal(signal.SIGINT, _stop)
        signal.signal(signal.SIGTERM, _stop)

        while not os.path.exists(args.logfile) and not stop["now"]:
            time.sleep(0.3)
        buf = ""
        if not stop["now"]:
            with open(args.logfile, encoding="utf-8") as fh:
                while not stop["now"]:
                    chunk = fh.readline()
                    if not chunk:
                        time.sleep(0.2)
                        continue
                    buf += chunk
                    if buf.endswith("\n"):
                        handle_line(buf, an, color)
                        buf = ""
        print()
    else:
        if not os.path.exists(args.logfile):
            sys.exit(f"[!] log file not found: {args.logfile}")
        with open(args.logfile, encoding="utf-8") as fh:
            for line in fh:
                handle_line(line, an, color)

    return summarize(an, args.logfile, color)


if __name__ == "__main__":
    sys.exit(main())