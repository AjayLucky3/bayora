FROM python:3.11-slim

LABEL maintainer="Ajay Doma <domaajay187@gmail.com>"
LABEL project="Bayora"
LABEL component="Blind Mediation Broker"

# Set secure environment settings
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LEDGER_DB_PATH="/var/lib/bayora/ledger.db"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user and persistent storage directory
RUN groupadd -g 10001 bayora && \
    useradd -u 10001 -g bayora -s /bin/sh -d /app bayora && \
    mkdir -p /var/lib/bayora && \
    chown -R bayora:bayora /app /var/lib/bayora

# Copy source files
COPY --chown=bayora:bayora main.py ledger.py ./

USER bayora

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
