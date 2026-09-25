# Web Cache Poisoning

## Description

This folder contains the code files to demonstrate a Web Cache Poisoning vulnerability in a Flask "forgot password" endpoint. The vulnerable version caches responses using only the request's URL path, while the actual content of the response depends on the Host header. This mismatch allows an attacker to send a single request with a spoofed Host, poisoning the shared cache so that every subsequent, completely legitimate user is served a password reset link pointing to the attacker's domain instead of the real one.

## Folder structure

    Vulnerable/   - vulnerable_app.py
    exploit/      - exploit.py
    Detection/    - detection and tracing files
    mitigated/    - app_mitigated.py

## Files

**Vulnerable/vulnerable_app.py** - Flask app with a `/forgot-password` endpoint that builds a password reset link using the request's Host header and caches the response by URL path only. Vulnerable to web cache poisoning.

**exploit/exploit.py** - sends a poisoning request with a spoofed Host header, followed by a normal, clean request to the same endpoint, proving that the clean request is served the attacker's poisoned link.

**mitigated/app_mitigated.py** - Security-enhanced version of the app. Rejects any request whose Host header is not on an approved allow-list, and includes the host in the cache key as a defence-in-depth measure, preventing the cache from being poisoned.

## Steps to run the program

If you have not installed the packages, run the following command on the terminal,

    python -m pip install flask requests

Navigate into the Vulnerable folder and run the app,

    cd Vulnerable
    python vulnerable_app.py

After running the above command you can view the app on,

    http://127.0.0.1:5000

Moreover you can exit the running app by clicking CTRL + C. Next, to run the exploit, open a new terminal, navigate into the exploit folder, and run the following command.

    cd exploit
    python exploit.py

By running the above command the app's vulnerability is exploited and the terminal prints the attacker's request, the normal user's request, and whether the exploit succeeded.

## Testing the mitigated version
 
Make sure `vulnerable_app.py` is stopped first (both apps use port 5000). Navigate into the mitigated folder and run the fixed app,
 
    cd mitigated
    python app_mitigated.py
 
Then, without changing anything, run the same exploit again from the exploit folder,
 
    cd exploit
    python exploit.py
 
This time the terminal should show that the exploit failed — the app rejects the spoofed Host header and the normal user is served the correct, legitimate reset link.