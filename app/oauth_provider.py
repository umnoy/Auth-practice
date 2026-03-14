import os
import re
import secrets
from urllib.parse import quote, urlencode

from flask import Flask, jsonify, redirect, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,30}$")

OAUTH_UI_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "ui", "oauth_provider")
)

app = Flask(
    __name__,
    template_folder=os.path.join(OAUTH_UI_DIR, "templates"),
    static_folder=os.path.join(OAUTH_UI_DIR, "static"),
)

USERS = {
    "ctf_player": {
        "login": "ctf_player",
        "name": "ctf player",
        "id": 1337,
        "password_hash": generate_password_hash("123456"),
    },
    "victim": {
        "login": "victim",
        "name": "Innocent User",
        "id": 9001,
        "password_hash": generate_password_hash("J<jw$n$ruZXd@AA46ROqY#uD}f~~AvX<8/b@E2d0"),
    },
}

pending_codes = {}
active_tokens = {}
next_user_id = 10000


@app.route("/register", methods=["GET", "POST"])
def register():
    global next_user_id

    client_id = request.args.get("client_id", "") if request.method == "GET" else request.form.get("client_id", "")
    redirect_uri = request.args.get("redirect_uri", "") if request.method == "GET" else request.form.get("redirect_uri", "")
    scope = request.args.get("scope", "") if request.method == "GET" else request.form.get("scope", "")

    if request.method == "GET":
        return render_template("register.html", error=None,
                               client_id=client_id, redirect_uri=redirect_uri, scope=scope)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    password_confirm = request.form.get("password_confirm", "")

    tpl_ctx = dict(client_id=client_id, redirect_uri=redirect_uri, scope=scope)

    if not USERNAME_RE.match(username):
        return render_template(
            "register.html",
            error="Username must be 3-30 characters: letters, digits, underscore only.",
            **tpl_ctx,
        ), 400

    if username in USERS:
        return render_template(
            "register.html", error="Username already taken.", **tpl_ctx,
        ), 409

    if len(password) < 6:
        return render_template(
            "register.html", error="Password must be at least 6 characters.", **tpl_ctx,
        ), 400

    if password != password_confirm:
        return render_template(
            "register.html", error="Passwords do not match.", **tpl_ctx,
        ), 400

    USERS[username] = {
        "login": username,
        "name": username,
        "id": next_user_id,
        "password_hash": generate_password_hash(password),
    }
    next_user_id += 1

    authorize_url = "/authorize?" + urlencode({"client_id": client_id, "redirect_uri": redirect_uri, "scope": scope})
    return redirect("/register/success?next=" + quote(authorize_url, safe=""))


@app.route("/register/success")
def register_success():
    next_url = request.args.get("next", "/authorize")
    return render_template("register_success.html", next_url=next_url)


@app.route("/authorize", methods=["GET", "POST"])
def authorize():
    if request.method == "GET":
        return render_template(
            "authorize.html",
            client_id=request.args.get("client_id"),
            redirect_uri=request.args.get("redirect_uri"),
            scope=request.args.get("scope", ""),
            error=None,
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")
    scope = request.form.get("scope", "")

    if (
        username not in USERS
        or not check_password_hash(USERS[username]["password_hash"], password)
    ):
        return (
            render_template(
                "authorize.html",
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                error="Incorrect username or password.",
            ),
            401,
        )

    code = secrets.token_urlsafe(16)
    pending_codes[code] = username

    return redirect(f"{redirect_uri}?code={code}")


@app.route("/token", methods=["POST"])
def token():
    code = request.form.get("code")
    if not code or code not in pending_codes:
        return jsonify({"error": "invalid_code"}), 400

    username = pending_codes.pop(code)
    access_token = secrets.token_urlsafe(24)
    active_tokens[access_token] = username

    return jsonify(
        {
            "access_token": access_token,
            "token_type": "bearer",
            "scope": "read:user",
        }
    )


@app.route("/user")
def user_info():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401

    token = auth[7:]
    if token not in active_tokens:
        return jsonify({"error": "invalid_token"}), 401

    username = active_tokens[token]
    user = USERS[username]
    return jsonify(
        {
            "login": user["login"],
            "name": user["name"],
            "id": user["id"],
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
