"""INTENTIONALLY VULNERABLE lab target — DO NOT deploy outside the isolated grin-lab network.
A 'ping host' form that passes user input straight to a shell (planted OS command injection)."""
import subprocess

from flask import Flask, request

app = Flask(__name__)

PAGE = """<!doctype html><title>netdiag</title>
<h1>Network Diagnostics</h1>
<form method=post action=/ping>
  host: <input name=host value="127.0.0.1">
  <button type=submit>ping</button>
</form>
<pre>{output}</pre>"""


@app.route("/")
def index():
    return PAGE.format(output="")


@app.route("/ping", methods=["POST"])
def ping():
    host = request.form.get("host", "")
    # PLANTED VULN: shell=True with unsanitised input -> command injection.
    try:
        out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True,
                             text=True, timeout=10)
        body = (out.stdout or "") + (out.stderr or "")
    except subprocess.TimeoutExpired:
        body = "timeout"
    return PAGE.format(output=body)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
