# Phishing URL Detection

A machine-learning project that classifies a submitted URL as **Phishing** or **Legitimate**. It includes a FastAPI backend, a trained Random Forest model, URL feature extraction, and a lightweight browser-based frontend.

> **Important:** The model scores URL-level features only. An optional *deep scan* can also look up DNS, the TLS certificate, domain age and the page itself, but those results are reported as separate evidence and do not change the model's probability. Treat everything as indicators, not as a guarantee that a website is safe or malicious.

## Contents

- [Features](#features)
- [Technology stack](#technology-stack)
- [Project structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Clone the repository](#1-clone-the-repository)
- [Set up and run the backend](#2-set-up-and-run-the-backend)
- [Run the frontend](#3-run-the-frontend)
- [Use the application](#4-use-the-application)
- [Configuration](#configuration)
- [Running the tests](#running-the-tests)
- [API reference](#api-reference)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)

## Features

- URL classification using a trained Random Forest model.
- Extraction of 14 lexical and structural URL features.
- Phishing and legitimate class-probability values.
- Browser-based interface for submitting URLs and viewing results.
- Feature details shown alongside the prediction.
- **SHAP explanations** in the API response: how much each feature pushed the score toward phishing or legitimate.
- **Strict URL validation** with clear error messages.
- **Domain heuristics** on every request: brand look-alikes (`paypa1.com`), brand names in unrelated domains, international-character tricks, link shorteners, frequently abused TLDs.
- **Optional deep scan**: DNS, TLS certificate, domain age (RDAP), Google Safe Browsing (with your own API key) and static page analysis (password forms that post to another site, hidden frames, redirects).
- **Hardening**: configurable CORS allow-list, per-client rate limiting, request IDs, JSON logs, `/health` and `/ready` endpoints.
- Automated tests and deployment files (Dockerfile, Render blueprint).
- FastAPI interactive API documentation.

## Technology stack

**Backend**

- Python
- FastAPI and Uvicorn
- Pandas and scikit-learn
- Joblib for loading saved model artifacts
- SHAP for explanations
- Requests for the optional domain-age and Safe Browsing lookups

**Frontend**

- HTML
- CSS
- Vanilla JavaScript
- Browser Fetch API

The current frontend is a static page in `frontend/index.html`; it does **not** require Node.js, npm, React, or a frontend build step.

## Project structure

```text
phishing-detection/
├── frontend/
│   ├── index.html
│   └── config.js
├── models/
│   ├── feature_columns.joblib
│   ├── phishing_rf_model.joblib
│   └── shap_explainer.joblib
├── notebooks/
│   └── 01_dataset_exploration.ipynb
├── src/
│   ├── __init__.py
│   ├── app.py
│   ├── config.py
│   ├── explain.py
│   ├── features.py
│   ├── logging_config.py
│   ├── model.py
│   ├── ratelimit.py
│   ├── validation.py
│   └── signals/
│       ├── __init__.py
│       ├── content.py
│       ├── domains.py
│       ├── netguard.py
│       ├── reputation.py
│       └── tls.py
├── tests/
├── .env.example
├── .gitignore
├── DEPLOYMENT.md
├── Dockerfile
├── README.md
├── pytest.ini
├── render.yaml
├── requirements-dev.txt
├── requirements-prod.txt
└── requirements.txt
```

- `frontend/index.html` — scanner UI and browser-side API requests.
- `frontend/config.js` — the one setting you change to point the frontend at a hosted API.
- `src/app.py` — FastAPI application: routes, CORS, rate limiting, request logging.
- `src/config.py` — settings read from environment variables.
- `src/validation.py` — URL validation.
- `src/features.py` — extracts the 14 features. **Do not change it without retraining the model.**
- `src/model.py` — loads the classifier and SHAP explainer and returns predictions.
- `src/explain.py` — converts SHAP output into the JSON returned by the API.
- `src/signals/` — domain heuristics and the deep scan. `netguard.py` is the safety layer for every outbound request.
- `src/ratelimit.py`, `src/logging_config.py` — rate limiter and JSON logging.
- `models/` — the trained Random Forest, its feature order and its SHAP explainer.
- `requirements.txt` — everything (including notebook tools); `requirements-prod.txt` — API runtime only, used by the Dockerfile; `requirements-dev.txt` — adds the test tools.
- `notebooks/01_dataset_exploration.ipynb` — dataset exploration notebook.

## Prerequisites

Install the following:

- **Git** — to clone the repository.
- **Python 3.12** — recommended for the pinned dependencies in `requirements.txt`.
- A modern web browser.

Check your Python installation:

```bash
python --version
```

On Windows, if `python` does not point to the intended version, try:

```powershell
py -3.12 --version
```

The model artifacts are already included in the repository, so you do not need to train the model to run the application.

## 1. Clone the repository

Replace `<YOUR_REPOSITORY_URL>` with the HTTPS or SSH URL of your Git repository:

```bash
git clone <YOUR_REPOSITORY_URL>
cd backend-phishing-detection-main
```

The directory name after cloning depends on the repository name. If your cloned folder has a different name, `cd` into that folder instead.

If you downloaded the project as a ZIP, extract it and open a terminal in the extracted project root—the directory containing `requirements.txt`, `src/`, `models/`, and `frontend/`.

## 2. Set up and run the backend

Run these commands from the **project root**, where `requirements.txt` is located.

### Create a virtual environment

**Windows PowerShell:**

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can use Command Prompt instead:

```bat
.venv\Scripts\activate.bat
```

**macOS / Linux:**

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

### Install Python dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If installation fails, confirm that the virtual environment is activated and that you are using Python 3.12. Do not install packages globally just to work around a virtual-environment problem.

### Start the API

From the same project root, run:

```bash
python -m uvicorn src.app:app --reload
```

The API should be available at:

- API base URL: `http://127.0.0.1:8000`
- Health check: `http://127.0.0.1:8000/`
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

Keep this terminal open while using the frontend.

The health check should return:

```json
{
  "message": "Phishing Detection API is running"
}
```

## 3. Run the frontend

Open a **second terminal** in the project root. Do not stop the backend terminal.

Run:

```bash
python -m http.server 5500 --directory frontend
```

Then open:

**http://127.0.0.1:5500**

This serves `frontend/index.html` locally. No `npm install` or frontend build is needed.

If your Python version does not support `--directory`, use:

```bash
cd frontend
python -m http.server 5500
```

Then open `http://127.0.0.1:5500`.

The frontend's API address defaults to the value in `frontend/config.js` (`http://127.0.0.1:8000`). If your backend is running at another address, enter that backend base URL in the field at the top of the page; this overrides the default for your browser only.

## 4. Use the application

1. Start the backend and frontend using the instructions above.
2. Open `http://127.0.0.1:5500`.
3. Confirm that the page reports **API connected**.
4. Enter a full URL, such as `https://example.com/login`, or choose one of the example URLs.
5. Select **Check URL**.
6. Review the classification, probability scores, and extracted URL features. The **Effect on score** column comes from SHAP.
7. Read **Other evidence** for the domain heuristics. Tick *Also look up the domain's age, DNS…* before checking to add the deep-scan results.

A “Legitimate” result is not proof that a site is safe. Avoid opening suspicious links just to test them.

## Configuration

The backend is configured with environment variables; every one has a default that works locally. Copy `.env.example` for the full list. The important ones:

| Variable | Default | Purpose |
| --- | --- | --- |
| `CORS_ALLOW_ORIGINS` | `http://127.0.0.1:5500,http://localhost:5500` | Origins allowed to call the API from a browser. Set it to your hosted frontend's exact origin in production. |
| `RATE_LIMIT_PER_MINUTE` | `30` | Per client, for `/predict`. `0` disables. |
| `DEEP_SCAN_RATE_LIMIT_PER_MINUTE` | `6` | Stricter per-client limit for deep scans. |
| `TRUSTED_PROXY_COUNT` | `0` | Reverse proxies in front of the app. Needed behind a host's proxy so each visitor gets their own rate-limit bucket (see `DEPLOYMENT.md`). |
| `ENABLE_EXPLANATIONS` | `true` | Load SHAP. Set `false` to save memory. |
| `ENABLE_DEEP_SCAN` | `true` | Set `false` so the server never visits submitted sites. |
| `SAFE_BROWSING_API_KEY` | unset | Optional; enables the Safe Browsing check in deep scans. |
| `LOG_LEVEL` | `INFO` | Log verbosity. |

Environment variables are read when the server starts. To use a `.env` file locally, export its values in your shell first (for example `set -a; source .env; set +a` on macOS/Linux).

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The tests cover URL validation, the feature extractor, SHAP output handling, the rate limiter, the domain heuristics, page analysis, and the network safety layer (using small local HTTP/TLS servers, so no internet access is needed). The HTTP-level tests in `tests/test_api.py` run when FastAPI's test client is installed.

## API reference

### `GET /`, `GET /health`, `GET /ready`

`/` checks that the backend is running. `/health` is a liveness check for uptime monitors. `/ready` reports whether the model and SHAP explainer are loaded.

```bash
curl http://127.0.0.1:8000/health
```

### `POST /predict`

Accepts a URL and returns the prediction, class probabilities, extracted features, SHAP contributions and extra signals.

**Request:**

```http
POST http://127.0.0.1:8000/predict
Content-Type: application/json
```

```json
{
  "url": "https://example.com/login",
  "explain": true,
  "deep_scan": false
}
```

| Field | Default | Meaning |
| --- | --- | --- |
| `url` | required | Must start with `http://` or `https://`, have a full domain name (or IP), no spaces or control characters, and be at most 2048 characters. |
| `explain` | `true` | Include SHAP `contributions` and `explanation`. |
| `deep_scan` | `false` | Also run the network checks (DNS, certificate, domain age, Safe Browsing, page content). Slower; the server visits the site. |

**Example response shape** (values are illustrative):

```json
{
  "url": "https://example.com/login",
  "prediction": "Legitimate",
  "phishing_probability": 0.12,
  "legitimate_probability": 0.88,
  "features": {
    "url_length": 25,
    "hostname_length": 11,
    "path_length": 6,
    "num_dots": 1,
    "num_hyphens": 0,
    "num_slashes": 3,
    "num_digits": 0,
    "num_special_chars": 5,
    "has_https": 1,
    "has_at_symbol": 0,
    "has_query": 0,
    "has_ip": 0,
    "num_subdomains": 0,
    "has_suspicious_keyword": 1
  },
  "contributions": {
    "url_length": -0.02,
    "has_suspicious_keyword": 0.09
  },
  "explanation": {
    "method": "shap_tree",
    "target_class": "phishing",
    "base_value": 0.41,
    "output_value": 0.12,
    "top_factors": [
      {
        "feature": "has_suspicious_keyword",
        "label": "Suspicious keyword",
        "value": 1,
        "contribution": 0.09,
        "direction": "toward_phishing"
      }
    ]
  },
  "signals": {
    "deep_scan": false,
    "domain_reputation": { "host_type": "domain", "registered_domain": "example.com" },
    "dns": null,
    "certificate": null,
    "domain_age": null,
    "safe_browsing": null,
    "content": null,
    "flags": []
  },
  "request_id": "9f2c0c1a5b7e4c6f8e0d3a4b5c6d7e8f"
}
```

How to read it:

- `contributions` has one number per feature: the SHAP value for the **phishing** class. Positive pushes toward phishing, negative toward legitimate. `explanation.base_value` plus the sum of the contributions is the explainer's estimate of `phishing_probability`. `contributions` and `explanation` are `null` if `explain` is false or the SHAP explainer could not be loaded.
- `signals.flags` lists findings, worst first, each with a `severity` (`high`, `warning`, `info`), a `code` and a plain-language `message`. Signals are evidence for a human to weigh; they never change `prediction` or the probabilities.
- Each deep-scan check has a `status`: `ok`, `skipped`, `unavailable`, `blocked`, `timeout` or `error`. A failing check never fails the request.

**Errors** always have a string `detail` (and, when relevant, a `request_id`): `422` invalid request or URL, `429` rate limit exceeded (see the `Retry-After` header), `413` body too large, `500` unexpected error (details are in the server log under the same `request_id`).

You can also send requests through the interactive Swagger UI at `http://127.0.0.1:8000/docs`.

### About the deep scan

When `deep_scan` is true, the **server** resolves the site's domain, opens a TLS connection, downloads up to ~300 KB of the page (no JavaScript is run, no cookies are sent), and asks `rdap.org` for the domain's registration date. If `SAFE_BROWSING_API_KEY` is set, the full URL is also sent to Google. Only use it with URLs you are comfortable sending to those services.

Because the server fetches addresses chosen by strangers, every outbound request goes through `src/signals/netguard.py`: hostnames must resolve only to public addresses (no loopback, private ranges or cloud metadata endpoints), the connection is pinned to the checked address, redirects are re-checked at every hop, and only ports 80 and 443 are allowed. Set `ENABLE_DEEP_SCAN=false` to turn the feature off completely.

## Deployment

See [`DEPLOYMENT.md`](DEPLOYMENT.md) for hosting the backend (Docker / Render) and the frontend (any static host), including CORS, rate limiting behind a proxy, logging and monitoring.

## Troubleshooting

### The frontend says the API is unavailable

- Confirm the backend terminal is still running.
- Open `http://127.0.0.1:8000/` directly in your browser.
- Check the API address field in the frontend.
- Check the browser developer tools' Console and Network tabs for errors.

### A CORS error appears

The backend only accepts browser requests from origins listed in `CORS_ALLOW_ORIGINS` (default: `http://127.0.0.1:5500` and `http://localhost:5500`). If you serve the frontend from another address or port, add that exact origin (scheme, host and port; no path or trailing slash) and restart the backend. Opening `frontend/index.html` directly from disk (`file://`) is not supported; use `python -m http.server`.

### I get "Too many requests"

The API limits each client to `RATE_LIMIT_PER_MINUTE` requests per minute (and fewer for deep scans). Wait for the time in the message, or raise the limit in your environment settings.

### Model files cannot be found

Run Uvicorn from the project root, not from inside `src/`. Verify that these files exist:

```text
models/phishing_rf_model.joblib
models/feature_columns.joblib
```

### Dependency installation fails

- Check `python --version` and use Python 3.12.
- Activate `.venv` before installing dependencies.
- Upgrade pip inside the virtual environment.
- Read the first package error in the installation output; later errors may be consequences of that first failure.

### Port 8000 or 5500 is already in use

Choose a free port. For example, start the API on another port with:

```bash
python -m uvicorn src.app:app --reload --port 8001
```

Then update the frontend API address to `http://127.0.0.1:8001`. To change the frontend port, pass a different port to `python -m http.server`.

## Limitations

- The model's score is based on URL-level lexical and structural features only. Deep-scan results are shown next to the score and are not fed into the model; combining them would need new training data and retraining.
- Domain heuristics are rules of thumb. The brand list is short and hand-written, and the "registered domain" logic is a simplified public-suffix check, so expect both false positives (a blog called `apple-recipes.com`) and misses.
- Deep-scan page analysis is static: it does not run JavaScript, so pages that build their forms in the browser look empty, and sites can serve different content to the scanner than to a visitor.
- Domain age depends on RDAP coverage for the TLD, and the Safe Browsing check uses the v4 Lookup API with your own key (check Google's terms for your use case).
- Rate limiting is in memory and per instance. If you run several instances, use a shared store or limit at the proxy.
- There is no authentication, and monitoring is limited to logs and health endpoints; see `DEPLOYMENT.md`.
- Model probabilities are estimates from the trained classifier, not absolute certainty.

## Future improvements

- Retrain the model with domain-age, certificate and content features, and evaluate whether they improve accuracy.
- Move rate-limit counters to Redis and add a metrics endpoint (for example Prometheus).
- Use the full Public Suffix List and a larger, maintained brand list.
- Move the Safe Browsing check to the v5 API.
- Add authentication or API keys if the API becomes public.

## License

No license is specified yet. Add a `LICENSE` file before distributing the project under an open-source license.

## Author

**Enoch**

Built as a minor project on **Phishing Website Detection Using Explainable AI**.
