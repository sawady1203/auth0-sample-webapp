# 📁 server.py -----

import argparse
import json
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

# OAuth registration will be done after parsing CLI arguments

@app.route("/")
def home():
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True),
        audience=env.get("AUTH0_AUDIENCE") # ← ここでも指定可能
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    print(token)
    session["user"] = token
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": client_id,
            },
            quote_via=quote_plus,
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Auth0 Flask server")
    parser.add_argument("--client-id", required=True, help="Auth0 Client ID")
    # Secret を引数に追加
    parser.add_argument("--client-secret", required=True, help="Auth0 Client Secret")
    parser.add_argument("--port", type=int, default=3000, help="Port to run the server on (default: 3000)")
    args = parser.parse_args()
    
    client_id = args.client_id
    client_secret = args.client_secret # 変数に格納
    port = args.port
    
    # Register OAuth
    oauth.register(
        "auth0",
        client_id=client_id,
        client_secret=client_secret, # Secret を渡す
        client_kwargs={
            "scope": "openid profile email",
            "code_challenge_method": "S256", # PKCE は引き続き有効
        },
        server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
        # token_endpoint_auth_method="none" は削除（デフォルトの Post/Basic を使用）
    )
    
    app.run(host="0.0.0.0", port=port)