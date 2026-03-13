import os
import secrets

from flask import Flask, jsonify, redirect, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash

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
