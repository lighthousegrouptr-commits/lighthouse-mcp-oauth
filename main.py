"""
Minimal OAuth 2.1 authorization server + reverse proxy wrapper for
Hermes MCP (mcp-proxy / hermes mcp serve).

Bu servis, Claude.ai'nin "Add custom connector" akışının beklediği
OAuth discovery + Dynamic Client Registration + Authorization Code (PKCE)
akışını minimal şekilde implemente eder ve doğrulanmış istekleri
arkadaki mcp-proxy'ye (varsayılan: http://hermes-mcp:8765) proxy'ler.

Tek kullanıcılıdır: /authorize isteği geldiğinde, ACCESS_PASSWORD ile
korunan basit bir onay sayfası gösterilir. Onaylanırsa authorization
code üretilir, /token ile access token'a çevrilir.

State in-memory'dir; container yeniden başlatılırsa mevcut
client/token kayıtları silinir (Claude.ai yeniden auth ister).
"""

import base64
import hashlib
import os
import secrets
import time
from typing import Optional

import httpx
from fastapi import FastAPI, Form, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse

# --- Yapılandırma -----------------------------------------------------

PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://mcp.lighthousegroup.net.tr")
UPSTREAM_BASE_URL = os.environ.get("UPSTREAM_BASE_URL", "http://hermes-mcp:8765")
ACCESS_PASSWORD = os.environ.get("ACCESS_PASSWORD", "")
ACCESS_TOKEN_TTL_SECONDS = int(os.environ.get("ACCESS_TOKEN_TTL_SECONDS", str(60 * 60 * 24 * 30)))  # 30 gün

if not ACCESS_PASSWORD:
    raise RuntimeError("ACCESS_PASSWORD ortam değişkeni tanımlanmalı")

app = FastAPI()

# --- In-memory state ----------------------------------------------------

# client_id -> { redirect_uris: [...], client_name, ... }
clients: dict[str, dict] = {}

# code -> { client_id, redirect_uri, code_challenge, code_challenge_method, expires_at }
auth_codes: dict[str, dict] = {}

# access_token -> { client_id, expires_at }
access_tokens: dict[str, dict] = {}


def now() -> float:
    return time.time()


def new_token(prefix: str = "") -> str:
    return prefix + secrets.token_urlsafe(32)


# --- OAuth Discovery ------------------------------------------------------

@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata():
    return JSONResponse(
        {
            "issuer": PUBLIC_BASE_URL,
            "authorization_endpoint": f"{PUBLIC_BASE_URL}/authorize",
            "token_endpoint": f"{PUBLIC_BASE_URL}/token",
            "registration_endpoint": f"{PUBLIC_BASE_URL}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            "scopes_supported": ["mcp"],
        }
    )


@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource_metadata():
    return JSONResponse(
        {
            "resource": PUBLIC_BASE_URL,
            "authorization_servers": [PUBLIC_BASE_URL],
            "bearer_methods_supported": ["header"],
        }
    )


# --- Dynamic Client Registration (RFC 7591) -------------------------------

@app.post("/register")
async def register_client(request: Request):
    body = await request.json()

    client_id = new_token("client_")
    client_secret = new_token("secret_")

    clients[client_id] = {
        "client_secret": client_secret,
        "redirect_uris": body.get("redirect_uris", []),
        "client_name": body.get("client_name", "mcp-client"),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "none"),
    }

    return JSONResponse(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_id_issued_at": int(now()),
            "redirect_uris": clients[client_id]["redirect_uris"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": clients[client_id]["token_endpoint_auth_method"],
        },
        status_code=201,
    )


# --- Authorization endpoint ------------------------------------------------

APPROVE_FORM_HTML = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <title>Hermes MCP - Erişim Onayı</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; background: #0A0E1A; color: #F5F1E8;
            display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
    form {{ background: #121826; border: 1px solid #232C40; border-radius: 12px; padding: 32px; width: 320px; }}
    h1 {{ font-size: 18px; margin: 0 0 8px; }}
    p {{ color: #8B95A8; font-size: 14px; margin: 0 0 20px; }}
    input {{ width: 100%; padding: 10px; border-radius: 8px; border: 1px solid #232C40;
             background: #0A0E1A; color: #F5F1E8; margin-bottom: 16px; box-sizing: border-box; }}
    button {{ width: 100%; padding: 10px; border-radius: 8px; border: none;
              background: #D4A24E; color: #0A0E1A; font-weight: 600; cursor: pointer; }}
    .err {{ color: #f87171; font-size: 13px; margin-bottom: 12px; }}
  </style>
</head>
<body>
  <form method="post" action="/authorize">
    <h1>Hermes MCP'ye erişim</h1>
    <p>{client_name} bu sunucuya bağlanmak istiyor.</p>
    {error_html}
    <input type="password" name="password" placeholder="Erişim şifresi" autofocus required />
    <input type="hidden" name="client_id" value="{client_id}" />
    <input type="hidden" name="redirect_uri" value="{redirect_uri}" />
    <input type="hidden" name="state" value="{state}" />
    <input type="hidden" name="code_challenge" value="{code_challenge}" />
    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}" />
    <button type="submit">Onayla ve Bağlan</button>
  </form>
</body>
</html>
"""


@app.get("/authorize")
async def authorize_get(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    response_type: str = Query("code"),
    state: str = Query(""),
    code_challenge: str = Query(""),
    code_challenge_method: str = Query("S256"),
):
    client = clients.get(client_id)
    client_name = client["client_name"] if client else "Bilinmeyen istemci"

    return HTMLResponse(
        APPROVE_FORM_HTML.format(
            client_name=client_name,
            error_html="",
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
    )


@app.post("/authorize")
async def authorize_post(
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form("S256"),
):
    client = clients.get(client_id)
    client_name = client["client_name"] if client else "Bilinmeyen istemci"

    if not secrets.compare_digest(password, ACCESS_PASSWORD):
        return HTMLResponse(
            APPROVE_FORM_HTML.format(
                client_name=client_name,
                error_html='<div class="err">Yanlış şifre, tekrar deneyin.</div>',
                client_id=client_id,
                redirect_uri=redirect_uri,
                state=state,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
            ),
            status_code=401,
        )

    code = new_token("code_")
    auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": now() + 600,  # 10 dakika
    }

    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}"
    if state:
        location += f"&state={state}"

    return RedirectResponse(location, status_code=302)


# --- Token endpoint ----------------------------------------------------------

def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if not code_challenge:
        # PKCE kullanılmıyorsa (önerilmez ama bazı client'lar atlayabilir)
        return True
    if method == "plain":
        return secrets.compare_digest(code_verifier, code_challenge)
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode()).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return secrets.compare_digest(expected, code_challenge)
    return False


@app.post("/token")
async def token_endpoint(request: Request):
    form = await request.form()
    grant_type = form.get("grant_type")

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    code = form.get("code")
    code_verifier = form.get("code_verifier", "")
    redirect_uri = form.get("redirect_uri", "")
    client_id = form.get("client_id", "")

    entry = auth_codes.get(code)
    if not entry or entry["expires_at"] < now():
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    if entry["client_id"] != client_id:
        return JSONResponse({"error": "invalid_client"}, status_code=400)

    if not verify_pkce(code_verifier, entry["code_challenge"], entry["code_challenge_method"]):
        return JSONResponse({"error": "invalid_grant", "error_description": "PKCE doğrulaması başarısız"}, status_code=400)

    # Code tek kullanımlık
    del auth_codes[code]

    access_token = new_token("at_")
    access_tokens[access_token] = {
        "client_id": client_id,
        "expires_at": now() + ACCESS_TOKEN_TTL_SECONDS,
    }

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
            "scope": "mcp",
        }
    )


# --- Bearer token doğrulama -------------------------------------------------

def is_valid_token(auth_header: Optional[str]) -> bool:
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return False
    token = auth_header.split(" ", 1)[1].strip()
    entry = access_tokens.get(token)
    if not entry:
        return False
    if entry["expires_at"] < now():
        del access_tokens[token]
        return False
    return True


def unauthorized_response() -> Response:
    www_auth = (
        f'Bearer resource_metadata="{PUBLIC_BASE_URL}/.well-known/oauth-protected-resource"'
    )
    return JSONResponse(
        {"error": "unauthorized"},
        status_code=401,
        headers={"WWW-Authenticate": www_auth},
    )


# --- Reverse proxy to mcp-proxy ----------------------------------------------

_client = httpx.AsyncClient(base_url=UPSTREAM_BASE_URL, timeout=None)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(path: str, request: Request):
    # OAuth/well-known endpoint'leri yukarıdaki route'lar tarafından
    # zaten karşılanıyor; buraya düşen her şey MCP trafiğidir ve
    # geçerli bir Bearer token gerektirir.
    if not is_valid_token(request.headers.get("authorization")):
        return unauthorized_response()

    url = f"/{path}"
    if request.url.query:
        url += f"?{request.url.query}"

    headers = dict(request.headers)
    headers.pop("host", None)

    body = await request.body()

    upstream_req = _client.build_request(
        request.method, url, headers=headers, content=body
    )
    upstream_resp = await _client.send(upstream_req, stream=True)

    return StreamingResponse(
        upstream_resp.aiter_raw(),
        status_code=upstream_resp.status_code,
        headers={
            k: v
            for k, v in upstream_resp.headers.items()
            if k.lower() not in ("content-length", "transfer-encoding", "connection", "date", "server")
        },
        background=None,
    )
