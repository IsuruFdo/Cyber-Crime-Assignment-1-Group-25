from flask import Flask, request

app = Flask(__name__)

cache = {}  # simple cache: path

@app.route("/forgot-password")
def forgot_password():
    # BUG: cache key ignores headers entirely
    cache_key = request.path

    if cache_key in cache:
        return cache[cache_key] + "<p><b>Cache: HIT</b></p>"

    # BUG: trusts a header the client can set themselves
    host = request.headers.get("X-Forwarded-Host", request.host)
    reset_link = f"http://{host}/reset?token=abc123"
    html = f"<h2>Password Reset</h2><a href='{reset_link}'>{reset_link}</a>"

    # BUG: caches the link, host and all
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