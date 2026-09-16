from flask import Flask, request, Response
import os

app = Flask(__name__)

# The directory the application intends users to be restricted to.
DOCUMENT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_files")

# The following route is intentionally vulnerable to Path Traversal attacks for demonstration purposes.
@app.route("/")
def index():
    return (
        "<h2>Vulnerable Document Portal</h2>"
        "<p>Try: <a href='/download?file=welcome.txt'>/download?file=welcome.txt</a></p>"
        "<p>This endpoint is intentionally vulnerable to Path Traversal for "
        "ISEC3004 Assignment 1 demonstration purposes only.</p>"
    )

@app.route("/download")
def download():
    """
    VULNERABLE CODE:
    The 'file' parameter supplied by the user is concatenated directly
    onto DOCUMENT_ROOT with no validation, no normalisation, and no check
    that the resolved path actually stays inside DOCUMENT_ROOT.

    An attacker can supply '../' sequences (or their URL-encoded form,
    %2e%2e%2f) to climb out of app_files/ and read any file the server
    process has permission to access.
    """
    requested_file = request.args.get("file", "")

    # vulnerable: no sanitisation of the requested file path
    # No sanitisation of 'requested_file' before use in a filesystem path.
    target_path = os.path.join(DOCUMENT_ROOT, requested_file)
    
    
    try:
        with open(target_path, "r", errors="replace") as f:
            content = f.read()
        return Response(content, mimetype="text/plain")
    except FileNotFoundError:
        return Response(f"File not found: {requested_file}", status=404)
    except PermissionError:
        return Response("Permission denied", status=403)
    except IsADirectoryError:
        return Response("Cannot read a directory", status=400)


if __name__ == "__main__":
    # Debug mode is left on for demo/tracing purposes only.
    # NEVER run debug=True in a real deployment.
    app.run(host="127.0.0.1", port=5000, debug=True)