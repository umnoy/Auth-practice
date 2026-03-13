import os
from collections import defaultdict

import requests
from flask import Flask, redirect, render_template, request, session, url_for

WEBAPP_UI_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "ui", "webapp")
)

app = Flask(
    __name__,
    template_folder=os.path.join(WEBAPP_UI_DIR, "templates"),
    static_folder=os.path.join(WEBAPP_UI_DIR, "static"),
)
app.secret_key = os.environ.get("SECRET_KEY", "super-secret-flask-key")

OAUTH_PROVIDER_URL = os.environ.get("OAUTH_PROVIDER_URL", "http://oauth-provider:5001")
OAUTH_PROVIDER_BROWSER_URL = os.environ.get(
    "OAUTH_PROVIDER_BROWSER_URL", "http://localhost:5001"
)
CLIENT_ID = "webapp-client-id"
CLIENT_SECRET = "webapp-client-secret"

user_notes = defaultdict(list)


@app.route("/")
def index():
    if "username" in session:
        return redirect("/dashboard")
    return render_template("index.html")


@app.route("/login")
def login():
    callback_url = url_for("callback", _external=True)
    return redirect(
        f"{OAUTH_PROVIDER_BROWSER_URL}/authorize"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={callback_url}"
        f"&scope=read:user"
    )


@app.route("/callback")
def callback():
    code = request.args.get("code")

    if not code:
        return render_template("error.html", message="No authorization code received."), 400

    callback_url = url_for("callback", _external=True)
    try:
        token_resp = requests.post(
            f"{OAUTH_PROVIDER_URL}/token",
            data={
                "code": code,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uri": callback_url,
            },
            timeout=5,
        )
        token_data = token_resp.json()
    except Exception as exc:
        return render_template("error.html", message=f"Token exchange failed: {exc}"), 500

    access_token = token_data.get("access_token")
    if not access_token:
        return render_template("error.html", message="No access token received."), 400

    try:
        user_resp = requests.get(
            f"{OAUTH_PROVIDER_URL}/user",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=5,
        )
        user_data = user_resp.json()
    except Exception as exc:
        return render_template("error.html", message=f"User fetch failed: {exc}"), 500

    username = user_data.get("login")
    if not username:
        return render_template("error.html", message="Could not get username."), 400

    session["username"] = username
    return redirect("/dashboard")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/")

    username = session["username"]
    notes = user_notes.get(username, [])
    return render_template("dashboard.html", username=username, notes=notes)


@app.route("/notes", methods=["POST"])
def add_note():
    if "username" not in session:
        return "", 401

    note = request.form.get("note", "").strip()
    if note:
        user_notes[session["username"]].append(note)

    return redirect("/dashboard")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
