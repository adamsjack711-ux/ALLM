FROM python:3.12-slim

# scrapy pulls a chunky transitive tree; install its system deps first.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2-dev libxslt1-dev libssl-dev gcc \
    && pip install --no-cache-dir scrapy==2.11.2 httpx==0.27.2 \
    && apt-get purge -y gcc libxml2-dev libxslt1-dev libssl-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY shared /app/shared
COPY scrapy_bot /app/scrapy_bot

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    CERNIS_TARGET=http://capture:8080

CMD ["python3", "-m", "scrapy_bot.runner"]
