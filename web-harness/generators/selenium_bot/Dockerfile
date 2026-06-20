FROM python:3.12-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir selenium==4.21.0 httpx==0.27.2

WORKDIR /app
COPY shared /app/shared
COPY selenium_bot /app/selenium_bot

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    ALLM_TARGET=http://capture:8080 \
    CHROME_BIN=/usr/bin/chromium \
    CHROMEDRIVER_BIN=/usr/bin/chromedriver

CMD ["python3", "-m", "selenium_bot.bot"]
