# Web Cache Poisoning - Detection and Tracing

ISEC3004 Assignment 1, Group 25. Detection / tracing role.

Shows how to **detect and trace** the attack in `../Vulnerable/vulnerable_app.py` (exploit: `../exploit/exploit.py`). The teammates' files are not modified.

## How it works

`instrumented_run.py` runs the teammates' app unchanged and writes one JSON line per request to `logs/wcp_forensic.log` (Host, X-Forwarded-Host, cache HIT/MISS, and which host the reset link points at). `wcp_detector.py` reads that log and raises alerts.

| Signal | Meaning | Level |
|---|---|---|
| `SPOOF_HEADER` | `X-Forwarded-Host` differs from the real Host | WARN |
| `POISON_WRITE` | that spoofed host was reflected into a cache MISS, so it is now stored | CRIT |
| `POISONED_HIT` | a cache HIT served a link to a host the client never asked for (the victim) | CRIT |

Verdict / exit code: `CLEAN` (0), `COMPROMISED` (1, a poisoned response reached a client), `SUSPICIOUS` (2, spoofed header seen but nobody was served poison).

## Run it (3 terminals, from this folder)

```
python3 instrumented_run.py --fresh                        # 1. app + logging
python3 wcp_detector.py logs/wcp_forensic.log --follow     # 2. live detector
python3 ../exploit/exploit.py                              # 3. attacker
```

Needs Python 3 with `flask` and `requests`. Port 5000 must be free. Alerts show up in terminal 2 as the exploit runs. Press Ctrl-C there to print the summary.

## Reading the result (paragraph for the report)

The log shows the attack as a two-request trace on one path. A request carrying `X-Forwarded-Host: evil-attacker.com` hits `/forgot-password` and is logged as a cache MISS whose served host is the attacker's value, which is the moment the cache is poisoned. A moment later a request with no such header is logged as a cache HIT, yet its served host is still `evil-attacker.com` instead of the real `127.0.0.1:5000`. A HIT returning content for a host the client never asked for is the decisive indicator: the response was replayed from the cache, not built for that client.

## Burp Suite cross-check

1. Open `http://127.0.0.1:5000/clear-cache` to start clean.
2. In Repeater send `GET /forgot-password` with the header `X-Forwarded-Host: evil-attacker.com`. Response shows the attacker link and `Cache: MISS`.
3. Remove the header and send again. Same attacker link, now `Cache: HIT`.
4. Check Proxy > HTTP history against `logs/wcp_forensic.log`. Both should show the same requests.

