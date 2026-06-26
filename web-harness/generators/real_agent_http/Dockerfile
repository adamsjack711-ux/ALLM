FROM python:3.12-slim

WORKDIR /app

COPY real_agent_http/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY shared /app/shared
COPY real_agent_http/__init__.py /app/real_agent_http/__init__.py
COPY real_agent_http/bot.py /app/real_agent_http/bot.py
# pricing.py is sibling to real_agent/ — copy from there.
COPY real_agent/pricing.py /app/real_agent/pricing.py

ENV PYTHONUNBUFFERED=1 \
    CERNIS_TARGET_APP=vampi \
    CERNIS_AGENT_BACKEND=openai \
    CERNIS_AGENT_MODEL=gpt-4o-mini

CMD ["python3", "/app/real_agent_http/bot.py"]
