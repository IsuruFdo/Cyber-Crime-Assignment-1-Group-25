from flask import Flask, request, Response
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

DOCUMENT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_files")
# Normalise once at startup so we always compare against the canonical root.
DOCUMENT_ROOT = os.path.realpath(DOCUMENT_ROOT)


@app.route("/")
def index():
    return (
        "<h2>Secured Document Portal</h2>"
        "<p>Try: <a href='/download?file=welcome.txt'>/download?file=welcome.txt</a></p>"
        "<p>Path traversal attempts against this endpoint are rejected.</p>"
    )


def is_safe_filename(name: str) -> bool:
    """
    LAYER 1: Reject obviously unsafe input outright.
    Blocks empty input, absolute paths, path separators, and '..'
    sequences before any filesystem call is made.
    """
    if not name:
        return False
    if ".." in name:
        return False
    if "/" in name or "\\" in name:
        return False
    if os.path.isabs(name):
        return False
    return True


@app.route("/download")
def download():
    """
    SECURITY-ENHANCED CODE:
    Every request is validated, sanitised, and the final resolved path
    is verified to remain inside DOCUMENT_ROOT before the file is opened.

    LAYER 1: Input validation — rejects obvious traversal characters
    ('..', '/', '\\') and absolute paths outright.

    LAYER 2: Filename sanitisation — secure_filename() strips the input
    down to a safe basename, removing any residual directory components
    or unusual characters (this is also what neutralises encoding-based
    bypass attempts, since any leftover '%' characters get stripped too).

    LAYER 3: Canonical path verification (the authoritative check) —
    resolves the final path with os.path.realpath() and confirms it is
    still located inside DOCUMENT_ROOT using os.path.commonpath(). This
    checks the REAL, resolved destination rather than trusting the input
    string, so it also protects against symlink-based bypasses and does
    not suffer from the known weakness of a naive str.startswith() check
    (which can be fooled by a sibling directory such as 'app_files_evil').
    """
    requested_file = request.args.get("file", "")

    # --- LAYER 1: input validation ---
    if not is_safe_filename(requested_file):
        return Response("Invalid filename.", status=400)

    # --- LAYER 2: filename sanitisation ---
    safe_name = secure_filename(requested_file)
    if not safe_name:
        return Response("Invalid filename.", status=400)

    # --- LAYER 3: canonical path verification (authoritative check) ---
    candidate_path = os.path.realpath(os.path.join(DOCUMENT_ROOT, safe_name))
    if os.path.commonpath([candidate_path, DOCUMENT_ROOT]) != DOCUMENT_ROOT:
        return Response("Access denied: path escapes document root.", status=403)

    try:
        with open(candidate_path, "r", errors="replace") as f:
            content = f.read()
        return Response(content, mimetype="text/plain")
    except FileNotFoundError:
        return Response(f"File not found: {safe_name}", status=404)
    except PermissionError:
        return Response("Permission denied", status=403)
    except IsADirectoryError:
        return Response("Cannot read a directory", status=400)


if __name__ == "__main__":
    # Debug mode disabled: Werkzeug's interactive debugger allows code
    # execution via its console if ever exposed, so it is turned off
    # here since this represents the "production-ready" secured version.
    app.run(host="127.0.0.1", port=5001, debug=False)