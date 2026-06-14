# lighthouse-mcp-oauth

Minimal OAuth 2.1 authorization server + reverse proxy wrapper, Hermes MCP'yi
(mcp-proxy / `hermes mcp serve`) Claude.ai'nin "Add custom connector" akışına
uyumlu hale getirmek için.

## Çalışma şekli

Claude.ai, custom connector eklerken OAuth discovery + Dynamic Client
Registration + Authorization Code (PKCE) akışı bekler. Bu servis bu akışı
minimal şekilde implemente eder ve doğrulanmış istekleri arkadaki
`mcp-proxy`'ye (varsayılan `http://hermes-mcp:8765`) proxy'ler.

Tek kullanıcılıdır: `/authorize` isteği geldiğinde `ACCESS_PASSWORD` ile
korunan basit bir HTML form gösterilir.

## Ortam değişkenleri

- `PUBLIC_BASE_URL` — bu servisin dışarıdan erişilen URL'i (örn. `https://mcp.lighthousegroup.net.tr/SECRET`)
- `UPSTREAM_BASE_URL` — arkadaki mcp-proxy adresi (örn. `http://hermes-mcp:8765`)
- `ACCESS_PASSWORD` — `/authorize` formundaki şifre (zorunlu)
- `ACCESS_TOKEN_TTL_SECONDS` — access token ömrü (varsayılan 30 gün)

## Çalıştırma

```bash
docker build -t lighthouse-mcp-oauth .
docker run -d --name mcp-oauth \
  --network dokploy-network \
  -e PUBLIC_BASE_URL="https://mcp.lighthousegroup.net.tr/SECRET" \
  -e UPSTREAM_BASE_URL="http://hermes-mcp:8765" \
  -e ACCESS_PASSWORD="..." \
  lighthouse-mcp-oauth
```

## Endpoint'ler

- `GET /.well-known/oauth-authorization-server` — RFC 8414 metadata
- `GET /.well-known/oauth-protected-resource` — protected resource metadata
- `POST /register` — Dynamic Client Registration (RFC 7591), kayıt tutmadan client_id/secret döner
- `GET|POST /authorize` — şifre formu, onaylanırsa authorization code üretir (PKCE)
- `POST /token` — code → access_token
- `/*` — diğer her şey, geçerli `Authorization: Bearer <token>` ile mcp-proxy'ye proxy'lenir
