# Deploying the app

The project has two parts that are hosted separately:

- **Backend** (`src/`, `models/`): a FastAPI app. Needs a host that runs a Python process or a Docker container. This guide uses [Render](https://render.com) because the repo includes a `render.yaml`, but the `Dockerfile` works on any container host (Railway, Fly.io, a VPS, Google Cloud Run...).
- **Frontend** (`frontend/`): plain HTML/JS. Any static host works (Netlify, Cloudflare Pages, Vercel, GitHub Pages). There is no build step.

Hosting providers change their plans, limits and dashboards often, so this guide describes *what to set*, not exact button labels. Check each provider's current docs for free-tier limits.

## The order matters

The frontend needs the backend's URL, and the backend needs the frontend's origin (for CORS). So:

1. Deploy the backend, note its public URL.
2. Put that URL in `frontend/config.js`, deploy the frontend, note its origin.
3. Set `CORS_ALLOW_ORIGINS` on the backend to the frontend's origin and restart the backend.

## 0. Before you start

- Push the project to a Git repository (GitHub, GitLab...). Do **not** commit `.env`; it is already in `.gitignore`.
- Optional: test the container locally (needs Docker):

  ```bash
  docker build -t phishing-api .
  docker run --rm -p 8000:8000 phishing-api
  curl http://127.0.0.1:8000/ready
  ```

  `/ready` should report `"model_loaded": true`. If `"explainer_loaded"` is `false`, the app still works but responses have no SHAP explanation; check the container logs for the reason.

## 1. Deploy the backend (Render)

1. Create a new **Web Service** from your repository (or use the repo's `render.yaml` as a Blueprint).
2. Choose the **Docker** runtime. Render finds the `Dockerfile` and injects the `PORT` variable, which the container already honours.
3. Set the **health check path** to `/health`.
4. Add environment variables:

   | Variable | Value |
   | --- | --- |
   | `CORS_ALLOW_ORIGINS` | Your frontend's origin, filled in at step 3 of "The order matters". Until then, leave the default. |
   | `TRUSTED_PROXY_COUNT` | See [Rate limiting behind a proxy](#rate-limiting-behind-a-proxy). |
   | `SAFE_BROWSING_API_KEY` | Optional. |
   | `RATE_LIMIT_PER_MINUTE`, `ENABLE_DEEP_SCAN`, ... | Optional; see `.env.example`. |

5. Deploy, then open `https://<your-service>/health` (should return `{"status":"ok"}`) and `https://<your-service>/docs`.

**Memory and cold starts.** Loading the SHAP explainer imports `shap` and `numba`, which is the heaviest part of startup. If your plan's instance runs out of memory or starts too slowly, set `ENABLE_EXPLANATIONS=false`: predictions keep working, just without explanations. Free instances commonly go to sleep when idle, so the first request after a pause can be slow; the frontend's 15-second timeout may fire once. Refreshing and trying again usually works.

**No Docker?** Use a native Python service instead: build command `pip install -r requirements-prod.txt`, start command `uvicorn src.app:app --host 0.0.0.0 --port $PORT --no-access-log --no-proxy-headers`, Python 3.12.

## 2. Deploy the frontend (any static host)

1. Edit `frontend/config.js`:

   ```js
   window.PHISH_CONFIG = {
     apiUrl: "https://<your-backend-host>"   // https, no trailing slash
   };
   ```

   Use `https://`. Browsers block a page served over HTTPS from calling an `http://` API ("mixed content").
2. Create a static site from the repository with **publish directory `frontend`** and **no build command**.
3. Open the site. The header should say **API connected**. If it says "API not reachable", see [Troubleshooting](#troubleshooting).
4. Copy the site's origin: scheme + host, no path, no trailing slash, for example `https://my-phishing-checker.netlify.app`.

## 3. Restrict CORS

On the backend, set:

```text
CORS_ALLOW_ORIGINS=https://my-phishing-checker.netlify.app
```

Several origins are comma-separated (for example the production site plus a custom domain). The match is exact, including `https` vs `http` and any port. Restart or redeploy the backend after changing it; settings are read at startup.

Avoid `*`: it lets any website call your API from a visitor's browser. (The app logs a warning at startup if you set it.)

CORS only controls which *websites* may call the API from a browser. It does not stop `curl` or scripts, which is why rate limiting exists.

## Rate limiting behind a proxy

The limiter keeps a counter per client address. On a hosting platform, all traffic reaches your app through the platform's proxy, so the app sees the proxy's address for everyone, unless it reads the `X-Forwarded-For` header the proxy adds.

- `TRUSTED_PROXY_COUNT=0` (default): the header is ignored. Safe, but behind a proxy **all visitors share one bucket**, so the 30th request in a minute from anyone blocks everyone.
- `TRUSTED_PROXY_COUNT=N`: the app uses the Nth address counting from the right of `X-Forwarded-For`. Only the proxies you control write the right-hand entries; clients can fake the left-hand ones, which is why counting from the right matters.

How to pick `N` (do not guess): deploy with `LOG_LEVEL=INFO`, make one request from your own machine, and look at the `client_ip` field in the request log line. Try `TRUSTED_PROXY_COUNT=1`. If `client_ip` is your real public address, you are done. If it is the platform's address, try `2` (for example when a CDN sits in front of the host's own proxy). Your public address is shown by any "what is my IP" site.

The counters live in the memory of one instance. With several instances, each keeps its own count; use a shared store (Redis) or rate-limit at the proxy instead.

## Logging

Every request produces one JSON line on stdout, which hosting dashboards collect:

```json
{"ts": "2026-10-15T07:41:52.088+00:00", "level": "INFO", "logger": "phishing_api.app", "message": "request", "request_id": "9f2c...", "client_ip": "203.0.113.9", "method": "POST", "path": "/predict", "status": 200, "duration_ms": 41.3}
```

A `prediction` line follows each scored URL with the **host** (not the full URL, which may contain private tokens), the verdict, the probability, whether SHAP and the deep scan ran, and the number of flags.

Clients can see the `request_id` in the `X-Request-ID` response header and in error bodies; search the logs for it to find what happened to a specific request. Unexpected errors are logged with a stack trace under the same id and returned to the client as a generic `500`.

Set `LOG_LEVEL=DEBUG` temporarily if you need more detail.

## Monitoring

The app exposes two endpoints for monitors:

- `GET /health`: the process is up. Use it for the host's health check and for an external uptime monitor (UptimeRobot, Better Stack, a cron job calling `curl`...). On a free host that sleeps, a ping every few minutes also keeps it awake; check your provider's rules before relying on that.
- `GET /ready`: the model is loaded; also shows whether the SHAP explainer loaded and whether deep scans are enabled.

Things worth watching in the logs:

| Look for | Meaning |
| --- | --- |
| `"status": 429` in bursts | Someone hitting the rate limit, or `TRUSTED_PROXY_COUNT` is wrong and everyone shares one bucket. |
| `"status": 500` | A bug; use the `request_id` to find the stack trace. |
| `duration_ms` far above normal | Deep scans are slow by nature (seconds); plain predictions should take milliseconds to tens of milliseconds. |
| `"message": "SHAP output ... does not match"` | `shap_explainer.joblib` was built from a different model than `phishing_rf_model.joblib`. Rebuild it. |
| `"SHAP explainer could not be loaded"` | `shap` is missing, or the library versions differ from the ones that created the file. |

Not included: metrics dashboards, alerting rules and error-tracking services. If you need them, add Prometheus metrics or a service such as Sentry; the request IDs and JSON logs are already in place to build on.

## The deep scan on a public server

The deep scan makes the server fetch pages that strangers name. The code defends against the main risk (being used to reach internal systems; see the README's "About the deep scan"), but you still decide whether to offer it:

- It sends the domain to `rdap.org`, and the full URL to Google if you set a Safe Browsing key. Mention this to your users.
- It is limited to 6 per minute per client by default.
- Set `ENABLE_DEEP_SCAN=false` to disable it completely; the rest of the API is unaffected.
- Some hosts restrict outbound connections; if every deep scan reports `error`, check your plan's network rules.

## Troubleshooting

**The page says "API not reachable".** Open `https://<your-backend>/health` directly. If that works, it is almost certainly CORS: check the browser console for a message mentioning CORS, and confirm `CORS_ALLOW_ORIGINS` exactly matches the address bar's origin (no trailing slash, right scheme). If it does not load, the backend is asleep, crashed or misconfigured: read its logs.

**Mixed content errors.** The frontend is on `https://` but `config.js` points to `http://`. Use the backend's `https://` URL.

**Everyone gets "Too many requests".** Probably `TRUSTED_PROXY_COUNT` is `0` behind a proxy; see [Rate limiting behind a proxy](#rate-limiting-behind-a-proxy).

**`/ready` shows `"explainer_loaded": false`.** Predictions work, but without SHAP. Read the startup logs: the usual causes are a missing `shap` package, a different `scikit-learn`/`shap` version than the one that created `models/shap_explainer.joblib`, or `ENABLE_EXPLANATIONS=false`.

**The container is killed or restarts.** Likely out of memory while loading SHAP; use a bigger instance or set `ENABLE_EXPLANATIONS=false`.

**The API address box shows an old address.** The box saves your edits in your browser. Clear it to fall back to `config.js`.
