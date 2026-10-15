// Where the frontend finds the backend API.
//
// Local development: leave as is (the backend runs on port 8000).
// Hosted deployment: set this to your backend's public https:// URL, with no
// trailing slash, e.g. "https://phishing-api.onrender.com". See DEPLOYMENT.md.
window.PHISH_CONFIG = {
  apiUrl: "http://127.0.0.1:8000"
};
