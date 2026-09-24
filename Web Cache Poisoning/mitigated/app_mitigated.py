from flask import Flask, request, abort

app = Flask(__name__)
cache = {}

# Only these hosts are considered legitimate. Anything else gets rejected.
ALLOWED_HOSTS = {"127.0.0.1:5000", "localhost:5000"}

@app.route("/forgot-password")
def forgot_password():
    host = request.host

    # FIX 1: reject any request claiming to be a host we don't recognize —
    # this blocks both X-Forwarded-Host AND Host header spoofing
    if host not in ALLOWED_HOSTS:
        abort(400, "Invalid Host header")

    # FIX 2: cache key now includes the host too, not just the path,
    # so even if this check were ever bypassed, different hosts can't
    # overwrite each other's cache entries
    cache_key = (request.path, host)

    if cache_key in cache:
        return cache[cache_key] + "<p><b>Cache: HIT</b></p>"

    reset_link = f"http://{host}/reset?token=abc123"
    html = f"<h2>Password Reset</h2><a href='{reset_link}'>{reset_link}</a>"

    cache[cache_key] = html
    return html + "<p><b>Cache: MISS</b></p>"

@app.route("/reset")
def reset():
    return "<h3>Reset form here</h3>"

@app.route("/clear-cache")
def clear_cache():
    cache.clear()
    return "Cache cleared."

if __name__ == "__main__":
    app.run(port=5000)