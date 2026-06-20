FROM python:3.12-slim

RUN pip install --no-cache-dir httpx==0.27.2 beautifulsoup4==4.12.3

WORKDIR /app
COPY shared /app/shared
COPY benign_bots /app/benign_bots

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    CERNIS_TARGET=http://capture:8080

CMD ["python3", "-m", "benign_bots.runner"]
