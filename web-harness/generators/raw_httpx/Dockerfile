FROM python:3.12-slim

RUN pip install --no-cache-dir httpx==0.27.2

WORKDIR /app
COPY shared /app/shared
COPY raw_httpx /app/raw_httpx

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    ALLM_TARGET=http://capture:8080

CMD ["python3", "-m", "raw_httpx.bot"]
