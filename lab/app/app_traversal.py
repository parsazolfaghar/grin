"""INTENTIONALLY VULNERABLE lab target (T4, expert) — path traversal -> credential disclosure.
DO NOT deploy outside the isolated grin-lab network. The /view endpoint joins user input to a base
directory without sanitisation, so `../` traversal reads arbitrary files — including a backup that
holds a password hash. The intended solve cracks that hash OFFLINE (john + rockyou) to recover the
SSH password, then logs in to read the flag. Harder than T3: it needs hash recognition + offline
cracking, not just a direct read."""
import os

from flask import Flask, abort, request

app = Flask(__name__)
BASE = "/srv/app/files"

PAGE = """<!doctype html><title>docstore</title>
<h1>Document Store</h1>
<p>view a file: <a href="/view?file=readme.txt">readme.txt</a></p>"""


@app.route("/")
def index():
    return PAGE


@app.route("/view")
def view():
    name = request.args.get("file", "")
    # PLANTED VULN: os.path.join with attacker-controlled input -> directory traversal / arbitrary read.
    path = os.path.join(BASE, name)
    try:
        with open(path) as fh:
            return "<pre>" + fh.read() + "</pre>"
    except OSError:
        abort(404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
