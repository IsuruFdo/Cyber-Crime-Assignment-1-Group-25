# Path Traversal - Detection and Tracing

ISEC3004 Assignment 1, Group 25. Detection / tracing role.

Shows how to **detect and trace** the attack in `../vulnerable_app.py` (exploit: `../exploit.py`). The teammates' files are not modified.

## How it works

The app already prints an access log with the full URL of every request, so nothing needs to be added to it. `pt_detector.py` reads that log. For every request with a `file` parameter it:

1. decodes the value repeatedly (catches double encoding such as `%252e%252e%252f`)
2. flags traversal patterns: `..`, absolute paths, drive letters, null bytes
3. works out whether the path climbs **out of** `app_files/`
4. uses the HTTP status to separate an attempt from a real leak (200 = the file was served)

| Signal | Meaning | Level |
|---|---|---|
| `TRAVERSAL_SUCCESS` | the path escapes `app_files/` and the server answered 200, so a file was read | CRIT |
| `TRAVERSAL_ATTEMPT` | traversal-looking input that did not leak a file (404 / 403 / stays inside the folder) | WARN |

Verdict / exit code: `CLEAN` (0), `COMPROMISED` (1, a file outside `app_files/` was served), `SUSPICIOUS` (2, payloads seen but none succeeded).

## Run it (from the `Path Traversal` folder)

```
python3 vulnerable_app.py 2>&1 | tee Detection/evidence/access.log     # terminal 1: app + saves its log
python3 exploit.py                                                     # terminal 2: attacker
python3 Detection/pt_detector.py Detection/evidence/access.log         # terminal 2: detector
```

Live version for the demo: `tail -f Detection/evidence/access.log | python3 Detection/pt_detector.py -` (Ctrl-C prints the summary). Needs Python 3 with `flask` and `requests`.

## Burp Suite cross-check

1. In Repeater send `GET /download?file=welcome.txt`. Normal file, HTTP 200.
2. Send `GET /download?file=../secret_config.txt`. The secret file comes back, HTTP 200.
3. Try variants: `..%2fsecret_config.txt`, `%252e%252e%252fsecret_config.txt`, `....//secret_config.txt`.
4. Check Proxy > HTTP history against `evidence/access.log`. Both should show the same requests.

## Evidence

`evidence/access.log` is the raw app log from the run and `evidence/detector_output.txt` is what the detector printed. The exploit script only prints its alternate payloads without sending them, so the extra variants in the log were sent by hand with `curl` (encoded slash, double-encoded, `....//`, deep `../../../../etc/passwd`). The last one returned 404 because it did not climb far enough to reach `/etc/passwd`. Screenshots to add: the exploit output, the detector alerts and summary, and Burp.
