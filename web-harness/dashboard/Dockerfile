FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/dashboard
COPY __init__.py /app/dashboard/__init__.py
COPY app.py /app/dashboard/app.py

EXPOSE 8095

# Bind to all interfaces inside the container; the compose service
# binds the host-side port to 127.0.0.1 only, so this isn't exposed
# off-host.
ENTRYPOINT ["python", "-m", "dashboard.app", "--host", "0.0.0.0", "--port", "8095"]
CMD ["--data-dir", "/data"]
