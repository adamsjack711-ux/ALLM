FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates \
    && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && apt-get purge -y git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir httpx==0.27.2

WORKDIR /app
COPY shared /app/shared
COPY sqlmap_bot /app/sqlmap_bot

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    CERNIS_TARGET=http://capture:8080

CMD ["python3", "-m", "sqlmap_bot.wrapper"]
