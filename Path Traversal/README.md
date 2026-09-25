# Path Traversal

## Description

This folder contains the code files to demonstrate Path traversal vulnerbility in a Flask file download endpoint. The vulnerable version blindly trusts a user-supplied file parameter when building a filesystem path, allowing an atter to escape the intended app.files/ directory using ../ sequences and read arbitrary files walse where on the server.

## Files

**Vulnerable_app.py** - Flask app with an unprotected /download?file= endpoint. Vulnerable to path traversal.

**exploit.py** - sends a legimate request and a traversal attack against vulnerable_app.py, proving the flaw.

**app_files/welcome.txt** - The legimatte, public file the app is intended to serve.

**secret_config.txt** - The dummy sensitive file paced outside app_files/, used to prove the traversal attack works

**mitigated_app.py** — Security-enhanced version of the same app. Validates, sanitises, and verifies the resolved path before serving a file, blocking traversal attempts.

## Steps to run the program

If you have not installed the packages, run the following command on the terminal,

    python -m pip install flask requests

To run the vulnerable code run the following command,

    python vulnerable_app.py

After running the above command you can view the app on,

    http://127.0.0.1:5000

Moreover you can exit the running app by clicking CTRL + C. Next to run the exploit app, on a new terminal run the following commands.

    python exploit.py

By running the above command the app's vulnerability is exploited and the text in the .txt files are printed in ther terminal.

### 2. Run the mitigated app

To run the security-enhanced version instead, run:

    python mitigated_app.py

This app runs on a different port:

    http://127.0.0.1:5001

In a new terminal, run the exploit script again — this time pointed at the mitigated app's port:

    python exploit.py 5001

The same traversal payload that succeeded against the vulnerable app is now rejected (`400 Bad Request`, "Invalid filename."), confirming the fix works. The legitimate request (`welcome.txt`) still succeeds normally, showing the mitigation does not break intended functionality.

You can stop the app by pressing `CTRL + C` in its terminal.