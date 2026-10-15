FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements-prod.txt .
RUN pip install -r requirements-prod.txt

COPY src ./src
COPY models ./models

RUN useradd --create-home appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

# Hosting platforms inject $PORT. --no-proxy-headers: the app reads X-Forwarded-For
# itself (TRUSTED_PROXY_COUNT), so uvicorn must not rewrite client addresses too.
CMD ["sh", "-c", "uvicorn src.app:app --host 0.0.0.0 --port ${PORT:-8000} --no-access-log --no-proxy-headers"]
