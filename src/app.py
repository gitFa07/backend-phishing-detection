from fastapi import FastAPI
from pydantic import BaseModel
from src.model import predict_url


app = FastAPI(
    title="Phishing URL Detection API",
    description="API for detecting phishing URLs using a Random Forest model",
    version="1.0.0",
)


class URLRequest(BaseModel):
    url: str


@app.get("/")
def root():
    return {
        "message": "Phishing Detection API is running"
    }


@app.post("/predict")
def predict(request: URLRequest):
    result = predict_url(request.url)


    return result

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])