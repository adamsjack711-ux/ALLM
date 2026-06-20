FROM node:20-bookworm-slim

# system chromium + a couple of fonts for headless rendering. We tell
# puppeteer-core to use this binary so the npm install doesn't have to
# download its own (puppeteer's default Chromium download is huge and
# brittle in CI).
RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium fonts-liberation ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY puppeteer_bot/package.json /app/
RUN PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true npm install --omit=dev

COPY shared /app/shared
COPY puppeteer_bot /app/puppeteer_bot

ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    ALLM_TARGET=http://capture:8080 \
    PYTHONUNBUFFERED=1 \
    NODE_ENV=production

# Re-use the python target_guard as an entrypoint pre-check, then exec node.
# Any non-loopback / non-allowlisted ALLM_TARGET hard-exits before node starts.
CMD ["sh", "-c", "python3 /app/shared/target_guard.py && exec node /app/puppeteer_bot/bot.js"]
