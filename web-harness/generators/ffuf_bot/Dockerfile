FROM python:3.12-slim

# ffuf is a Go binary; grab the pinned release. Pinning the version
# keeps the build reproducible and avoids any "latest" surprises.
ARG FFUF_VERSION=2.1.0
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && curl -fL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" \
        -o /tmp/ffuf.tgz \
    && tar -xzf /tmp/ffuf.tgz -C /usr/local/bin/ ffuf \
    && rm /tmp/ffuf.tgz \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir httpx==0.27.2

WORKDIR /app
COPY shared /app/shared
COPY ffuf_bot /app/ffuf_bot

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    CERNIS_TARGET=http://capture:8080

CMD ["python3", "-m", "ffuf_bot.wrapper"]
