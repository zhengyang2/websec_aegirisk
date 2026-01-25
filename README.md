# websec_aegirisk

to start risk engine API in root folder

```

uvicorn risk_engine.api:app --reload --port 8001

```
to see api opened use localhost/docs



to start web app 
inside webapp/webapp
```commandline
uvicorn app.main:app --reload --port 8080

start with PC ip
 uvicorn app.main:app --reload --host 0.0.0.0 --port 8003


```



## Risk Engine API key 

every request from web need to tag along API key to secure the RBA API







## Cookie API 

```route
/cookie/generate
```
This endpoint is called server-to-server by the web application after a successful login. It returns either:

a newly issued/rotated raw device token (to be delivered to the client by the web app), or

no new token if rotation is not required.

endpoint JSON format
```JSON
accepts 
{
  "user_id": "string",
  "device_id": "string",
  "force_rotate": false (optional)
}

return 
{
  "case": "first_issue | risk_rotate | periodic_rotate | no_rotate",
  "rotate": true,
  "raw_token": "string | null",
  "expires_at_utc": "ISO-8601 string | null",
  "cookie_name": "__Host_rba_dt"
}
```



## Cookie Name
**app_device_id**

Web-application–issued, opaque device identifier used for login continuity and risk context across sessions.

**__Host_rba_dt**

Risk-engine–issued trusted device token used to recognize previously verified devices after successful authentication.

```
HttpOnly – prevents JavaScript access (XSS protection)

Secure – sent only over HTTPS (production)

SameSite=Lax – mitigates CSRF while allowing normal navigation

Path=/ – available across the entire application

Domain not set – host-only to prevent subdomain injection

Max-Age – max age of cookie
```