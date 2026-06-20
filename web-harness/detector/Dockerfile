FROM python:3.12-slim

# CPU torch wheels are big but the runtime is small. Cache-friendly.
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY features.py model.py train.py eval.py alerter.py heldout.py /app/

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

ENTRYPOINT ["python3"]
CMD ["train.py"]
