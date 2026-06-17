"""INTENTIONALLY VULNERABLE lab target (T5, elite) — Jinja2 server-side template injection -> RCE.
DO NOT deploy outside the isolated grin-lab network. The `name` parameter is concatenated into a
template string and rendered, so `{{ ... }}` payloads execute (e.g. `{{7*7}}` proves it, then a
gadget chain runs commands). RCE lands as a low-priv user; root requires SUID enumeration + a
GTFOBins SUID technique (the box ships a SUID `find`). Harder than T3: SSTI payload crafting is
subtler than `;cmd`, and the privesc is SUID-based rather than `sudo -l`."""
from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/")
def index():
    name = request.args.get("name", "guest")
    # PLANTED VULN: user input concatenated into the template source -> SSTI (and thus RCE).
    tpl = "<!doctype html><title>portal</title><h1>Hello, " + name + "!</h1><p>welcome.</p>"
    return render_template_string(tpl)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
