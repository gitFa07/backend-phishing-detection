# Phishing URL Detection — Backend API

A FastAPI-based backend for detecting potentially phishing URLs using a trained **Random Forest classifier**. The API accepts a URL, extracts lexical and structural features from it, runs the trained model, and returns the prediction, class probabilities, and extracted features.

## Features

- REST API built with **FastAPI**
- Random Forest model for phishing URL classification
- Automatic URL feature extraction
- Phishing and legitimate probability scores
- Returns extracted features for transparency/debugging
- Saved model artifacts loaded with `joblib`
- Interactive API documentation through FastAPI / Swagger UI
- SHAP explainer artifact included for explainability work

---

## Project Structure

```text
backend-phishing-detection/
│
├── models/
│   ├── feature_columns.joblib
│   ├── phishing_rf_model.joblib
│   └── shap_explainer.joblib
│
├── notebooks/
│   └── 01_dataset_exploration.ipynb
│
├── src/
│   ├── __init__.py
│   ├── app.py
│   ├── features.py
│   └── model.py
│
├── .gitignore
└── requirements.txt
```

### Main Components

| File | Purpose |
|---|---|
| `src/app.py` | Defines the FastAPI application and API endpoints |
| `src/features.py` | Extracts features from submitted URLs |
| `src/model.py` | Loads the trained model and performs predictions |
| `models/phishing_rf_model.joblib` | Trained Random Forest classifier |
| `models/feature_columns.joblib` | Stores the feature order used during model training |
| `models/shap_explainer.joblib` | Saved SHAP explainer for future/extended explainability |
| `notebooks/01_dataset_exploration.ipynb` | Dataset exploration and analysis |

---

## Tech Stack

- **Python**
- **FastAPI**
- **Uvicorn**
- **Pydantic**
- **Pandas**
- **NumPy**
- **Scikit-learn**
- **Joblib**
- **SHAP**

---

## How It Works

The prediction pipeline is:

```text
Client
  │
  │ POST /predict
  ▼
FastAPI
  │
  ▼
URL Feature Extraction
  │
  ├── URL length
  ├── Hostname length
  ├── Path length
  ├── Number of dots
  ├── Number of hyphens
  ├── Number of slashes
  ├── Number of digits
  ├── Number of special characters
  ├── HTTPS usage
  ├── @ symbol
  ├── Query string
  ├── IP address usage
  ├── Number of subdomains
  └── Suspicious keywords
  │
  ▼
Random Forest Model
  │
  ▼
Prediction + Probabilities + Features
  │
  ▼
JSON Response
```

---

## URL Features

The backend extracts the following features from each URL:

### Length-based features

- `url_length`
- `hostname_length`
- `path_length`

### Character-based features

- `num_dots`
- `num_hyphens`
- `num_slashes`
- `num_digits`
- `num_special_chars`

### Security / structural features

- `has_https`
- `has_at_symbol`
- `has_query`
- `has_ip`
- `num_subdomains`

### Suspicious-content feature

The backend checks for suspicious keywords such as:

```text
login
signin
verify
verification
account
update
secure
password
bank
confirm
authenticate
wallet
payment
```

If one or more of these words appear in the URL, `has_suspicious_keyword` is set to `1`.

> **Important:** These features are heuristic URL-level indicators. A prediction should be treated as a machine-learning classification result, not as a definitive security verdict.

---

# Installation

## 1. Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd backend-phishing-detection
```

## 2. Create a virtual environment

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

# Running the API Locally

From the project root, run:

```bash
uvicorn src.app:app --reload
```

The server will start on:

```text
http://127.0.0.1:8000
```

You should see output similar to:

```text
Uvicorn running on http://127.0.0.1:8000
```

---

# API Documentation

FastAPI automatically provides interactive documentation.

### Swagger UI

Open:

```text
http://127.0.0.1:8000/docs
```

### ReDoc

Open:

```text
http://127.0.0.1:8000/redoc
```

These interfaces allow you to test the API directly from your browser.

---

# API Endpoints

## `GET /`

Health/status endpoint used to verify that the API is running.

### Request

```http
GET /
```

### Response

```json
{
  "message": "Phishing Detection API is running"
}
```

---

## `POST /predict`

Classifies a URL as either **Phishing** or **Legitimate**.

### Request

```http
POST /predict
Content-Type: application/json
```

### Request Body

```json
{
  "url": "https://example.com/login"
}
```

### Example cURL Request

```bash
curl -X POST "http://127.0.0.1:8000/predict" \
     -H "Content-Type: application/json" \
     -d "{\"url\":\"https://example.com/login\"}"
```

### Example Response

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
  }
}
```

The exact probabilities and feature values depend on the submitted URL and trained model.

---

# Using Postman

1. Start the backend:

```bash
uvicorn src.app:app --reload
```

2. Create a new **POST** request.

3. Set the URL to:

```text
http://127.0.0.1:8000/predict
```

4. Select:

```text
Body → raw → JSON
```

5. Send:

```json
{
  "url": "https://example.com"
}
```

6. Click **Send**.

The server will return the classification result as JSON.

---

# Model Architecture

The backend uses a pre-trained **Random Forest classifier**.

The model artifacts are stored in the `models/` directory:

```text
models/
├── phishing_rf_model.joblib
├── feature_columns.joblib
└── shap_explainer.joblib
```

At application startup, `src/model.py` loads these artifacts.

The feature columns are also loaded and used to ensure that the features supplied to the model are in the **same order as during training**.

This is important because scikit-learn models expect their input features to correspond to the feature ordering used during training.

---

# Prediction Logic

The backend performs the following operations:

1. Receive a URL through `/predict`.
2. Parse the URL using Python's `urllib.parse`.
3. Extract lexical and structural features.
4. Convert the feature dictionary into a Pandas DataFrame.
5. Reorder the columns using `feature_columns.joblib`.
6. Pass the features to the Random Forest model.
7. Generate the predicted class.
8. Generate class probabilities using `predict_proba()`.
9. Convert the numeric class into:
   - `Phishing`
   - `Legitimate`
10. Return the prediction, probabilities, and extracted features.

---

# Explainability

The project includes a serialized SHAP explainer:

```text
models/shap_explainer.joblib
```

The current `/predict` implementation loads the SHAP explainer but does not yet return SHAP values in the API response.

This artifact can be used to extend the API with explainable predictions, for example:

```text
URL
 ↓
Extract Features
 ↓
Random Forest Prediction
 ↓
SHAP Explanation
 ↓
Prediction + Feature Contributions
```

A future explainability endpoint could return the features that contributed most strongly toward the phishing or legitimate classification.

---

# Production Deployment

For production, the application can be started with Uvicorn without the development reload option:

```bash
uvicorn src.app:app --host 0.0.0.0 --port $PORT
```

The `$PORT` variable is useful on hosting platforms that dynamically assign the application port.

For example, a deployment platform may provide a public API URL such as:

```text
https://your-backend-domain.example.com
```

The frontend should then send requests to:

```text
https://your-backend-domain.example.com/predict
```

rather than the local:

```text
http://127.0.0.1:8000/predict
```

---

# Environment Configuration

The current backend does not require environment variables for its model paths because the model files are resolved relative to the project directory.

If secrets, external services, databases, or configurable deployment values are added later, they should be stored in environment variables rather than committed to the repository.

The `.gitignore` already excludes:

```text
.env
.venv/
__pycache__/
*.pyc
data/
.ipynb_checkpoints/
```

---

# Error Handling

FastAPI/Pydantic validates the incoming request body.

A valid request must contain a `url` field:

```json
{
  "url": "https://example.com"
}
```

For example, a request without the required field will result in a validation error from FastAPI.

---

# Development

To run the server with automatic reload during development:

```bash
uvicorn src.app:app --reload
```

When modifying:

- `src/app.py` → API routes and request/response handling
- `src/features.py` → URL feature engineering
- `src/model.py` → prediction pipeline

the development server will automatically reload.

---

# Notes and Limitations

- The classifier operates on URL-level features and does not currently fetch or inspect the webpage itself.
- Domain reputation, DNS information, certificate details, page content, redirects, and other external signals are not currently used.
- The presence of words such as `login` or `verify` does not inherently mean that a URL is malicious.
- Model probabilities represent the trained classifier's estimated class probabilities and should not be interpreted as absolute confidence.
- The trained model artifacts must remain compatible with the versions of scikit-learn and related libraries used to create them.
- The current API does not implement authentication, rate limiting, request logging, or production-grade monitoring.

---

# Future Improvements

Potential extensions include:

- [ ] Add SHAP-based explanations to `/predict`
- [ ] Add a dedicated `/explain` endpoint
- [ ] Add CORS configuration for the frontend
- [ ] Add stronger URL validation
- [ ] Add more lexical and domain-based features
- [ ] Add DNS/domain reputation features
- [ ] Add SSL/TLS certificate features
- [ ] Add webpage-content analysis
- [ ] Add API authentication
- [ ] Add rate limiting
- [ ] Add structured logging
- [ ] Add automated tests
- [ ] Add Docker support
- [ ] Add CI/CD
- [ ] Add model versioning and performance monitoring

---

# Example Frontend Integration

A JavaScript/TypeScript frontend can call the API using `fetch`:

```javascript
const response = await fetch("http://127.0.0.1:8000/predict", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    url: "https://example.com",
  }),
});

const result = await response.json();

console.log(result);
```

When the backend is deployed, replace the local API URL with the deployed backend URL.

---

# License

Add your preferred license here, for example:

```text
MIT License
```

---

## Author

**Enoch**

Built as part of a project on **Phishing Website Detection Using Explainable AI**.
