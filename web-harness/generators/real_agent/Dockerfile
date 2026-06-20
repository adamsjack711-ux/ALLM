FROM mcr.microsoft.com/playwright/python:v1.50.0-noble

# Browser-use ships a Playwright-based agent. The base image bundles
# Chromium / Firefox / WebKit; we install the Python `playwright` binding
# at the matching version and then layer browser-use + the LLM client
# libs on top.
RUN pip install --no-cache-dir --break-system-packages \
        playwright==1.50.0

WORKDIR /app
COPY shared /app/shared
COPY real_agent/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -r /app/requirements.txt
COPY real_agent/bot.py /app/

ENV PYTHONUNBUFFERED=1 \
    CERNIS_TARGET=http://capture:8080 \
    CERNIS_TARGET_APP=dvwa \
    CERNIS_AGENT_BACKEND=openai \
    CERNIS_AGENT_MODEL=gpt-4o-mini \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

CMD ["python3", "/app/bot.py"]
