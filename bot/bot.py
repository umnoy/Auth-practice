import os
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests as http_requests
from flask import Flask, render_template, request

BOT_UI_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ui", "bot"))

app = Flask(
    __name__,
    template_folder=os.path.join(BOT_UI_DIR, "templates"),
    static_folder=os.path.join(BOT_UI_DIR, "static"),
)

FLAG = os.environ.get("FLAG", "practice{csrf_l0gin_y0u_auth3d_as_m3}")
WEBAPP_INTERNAL_URL = os.environ.get("WEBAPP_INTERNAL_URL", "http://webapp:5000")
WEBAPP_INTERNAL_PARSED = urlparse(WEBAPP_INTERNAL_URL)

ALLOWED_EXTERNAL_SCHEME = "http"
ALLOWED_EXTERNAL_HOSTS = {"localhost", "127.0.0.1"}
ALLOWED_EXTERNAL_PORT = 5000
ALLOWED_EXTERNAL_PATHS = {"/callback"}


def validate_submitted_url(url):
    parsed = urlparse(url)

    if parsed.scheme != ALLOWED_EXTERNAL_SCHEME:
        return None, "Only http:// links are allowed."

    if parsed.username or parsed.password:
        return None, "Credentials in URL are not allowed."

    if parsed.hostname not in ALLOWED_EXTERNAL_HOSTS or parsed.port != ALLOWED_EXTERNAL_PORT:
        return None, "URL must point to localhost:5000."

    if parsed.path not in ALLOWED_EXTERNAL_PATHS:
        return None, "Only /callback links are allowed."

    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not query.get("code"):
        return None, "Callback URL must include a non-empty code parameter."

    if parsed.fragment:
        return None, "URL fragments are not allowed."

    return parsed, None


def to_internal_url(parsed):
    normalized_query = urlencode(parse_qsl(parsed.query, keep_blank_values=True), doseq=True)
    return urlunparse(
        (
            WEBAPP_INTERNAL_PARSED.scheme,
            WEBAPP_INTERNAL_PARSED.netloc,
            parsed.path,
            "",
            normalized_query,
            "",
        )
    )


def safe_click(session, start_url, max_redirects=4):
    current = start_url
    for _ in range(max_redirects + 1):
        resp = session.get(current, timeout=5, allow_redirects=False)
        if not resp.is_redirect and not resp.is_permanent_redirect:
            return resp

        location = resp.headers.get("Location")
        if not location:
            return resp

        next_url = urljoin(current, location)
        parsed_next = urlparse(next_url)
        if (
            parsed_next.scheme != WEBAPP_INTERNAL_PARSED.scheme
            or parsed_next.netloc != WEBAPP_INTERNAL_PARSED.netloc
        ):
            raise ValueError("Blocked external redirect")
        current = next_url

    raise ValueError("Too many redirects")


@app.route("/")
def index():
    return render_template("index.html", message=None, msg_class="")


@app.route("/submit", methods=["POST"])
def submit():
    url = request.form.get("url", "").strip()

    if not url:
        return render_template("index.html", message="Please provide a URL.", msg_class="msg-err")

    parsed, error = validate_submitted_url(url)
    if error:
        return render_template("index.html", message=error, msg_class="msg-err")

    try:
        session = http_requests.Session()
        internal_url = to_internal_url(parsed)
        safe_click(session, internal_url)
        session.post(
            f"{WEBAPP_INTERNAL_URL}/notes",
            data={"note": FLAG},
            timeout=5,
        )
    except Exception:
        pass

    return render_template(
        "index.html",
        message="Admin has reviewed your link. Thank you for the report!",
        msg_class="msg-ok",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
