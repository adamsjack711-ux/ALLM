FROM perl:5.40-slim

# nikto is a Perl tool — clone the upstream repo and symlink the entry
# point. The repo is small (~20 MB) and pinning to a known release tag
# keeps the build reproducible. Python is here for the httpx wrapper +
# the target_guard pre-exec.
ARG NIKTO_REF=2.5.0
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates python3 python3-pip \
        libnet-ssleay-perl libcrypt-ssleay-perl \
    && git clone --depth 1 -b ${NIKTO_REF} https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && pip install --no-cache-dir --break-system-packages httpx==0.27.2 \
    && apt-get purge -y git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY shared /app/shared
COPY nikto_bot /app/nikto_bot

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    CERNIS_TARGET=http://capture:8080

CMD ["python3", "/app/nikto_bot/wrapper.py"]
