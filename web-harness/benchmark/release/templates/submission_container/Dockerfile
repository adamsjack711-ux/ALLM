FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY submission.py runner.py ./

ENV CERNIS_IN=/in
ENV CERNIS_OUT=/out
ENV PYTHONUNBUFFERED=1

USER nobody

ENTRYPOINT ["python", "/app/runner.py"]
