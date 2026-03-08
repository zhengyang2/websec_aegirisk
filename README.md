# websec_aegirisk

## Setup

1. Install dependencies.

```powershell
pip install -r requirements.txt
```

2. Create `risk_engine/.env`.

```env
RISK_ENGINE_ENFORCE_API_KEY=1
```

3. Start the risk engine API from the project root.

```powershell
uvicorn risk_engine.api:app --reload --port 8003
```

4. Call the setup endpoint once to generate `engine_state.json` and return an API key.

```powershell
$setup = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8003/setup
$setup.api_key
```

5. Create `web_app/WebApp/app/web.env` and paste the generated API key.
  You can get it from `engine_state.json` or directly from `$setup.api_key`.

```env
RISK_ENGINE_API_KEY="<API-KEY>"
```

6. Start the web app in another terminal.

```powershell
cd web_app\WebApp
uvicorn app.main:app --reload --port 8080
```

Optional (for LAN testing):

```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
```

## Useful Local URLs

- Risk engine docs: `http://127.0.0.1:8003/docs`
- Risk engine dashboard: `http://127.0.0.1:8003`
- Web app: `http://127.0.0.1:8080`

Use the generated API key to log in to the risk engine dashboard.

## Risk Engine API Key

Every request from the web app to the risk engine must include this API key.

## Cookie API

Route:

```text
/cookie/generate
```

This endpoint is called server-to-server by the web application after a successful login. It returns either:

- a newly issued or rotated raw device token (to be delivered to the client by the web app), or
- no new token if rotation is not required.

Request and response format:

```json
{
  "request": {
    "user_id": "string",
    "device_id": "string",
    "force_rotate": false
  },
  "response": {
    "case": "first_issue | risk_rotate | periodic_rotate | no_rotate",
    "rotate": true,
    "raw_token": "string | null",
    "expires_at_utc": "ISO-8601 string | null",
    "cookie_name": "__Host_rba_dt"
  }
}
```

## Cookie Names

`app_device_id`

Web-application-issued, opaque device identifier used for login continuity and risk context across sessions.

`__Host_rba_dt`

Risk-engine-issued trusted device token used to recognize previously verified devices after successful authentication.

Cookie security expectations:

```text
HttpOnly: prevents JavaScript access (XSS protection)
Secure: sent only over HTTPS (production)
SameSite=Lax: mitigates CSRF while allowing normal navigation
Path=/: available across the entire application
Domain not set: host-only to prevent subdomain injection
Max-Age: max age of cookie
```
