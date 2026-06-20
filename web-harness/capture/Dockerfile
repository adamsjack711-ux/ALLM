FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY proxy.py honeypots.py beacon.js /app/

ENV PYTHONUNBUFFERED=1 \
    UPSTREAM=http://dvwa:80 \
    DATA_DIR=/data

EXPOSE 8080 8090

CMD ["python3", "proxy.py"]
