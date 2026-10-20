FROM python:3.11-slim

LABEL maintainer="Ajay Doma <domaajay187@gmail.com>"
LABEL project="Bayora"
LABEL component="Red Team Adversarial Client"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install curl and iputils for network isolation probing
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd -g 10004 redrunner && \
    useradd -u 10004 -g redrunner -s /bin/sh -d /app redrunner && \
    chown -R redrunner:redrunner /app

COPY --chown=redrunner:redrunner client.py ./

USER redrunner

# Keep container idle for manual command execution or run adversarial test suite
CMD ["python", "client.py"]
