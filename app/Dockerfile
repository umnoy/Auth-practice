FROM python:3.11-slim

WORKDIR /app

COPY app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r ./requirements.txt

COPY app/ ./app/
COPY ui/ ./ui/

WORKDIR /app/app

EXPOSE 5000 5001