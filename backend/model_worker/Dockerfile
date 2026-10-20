FROM python:3.11-slim

LABEL maintainer="Ajay Doma <domaajay187@gmail.com>"
LABEL project="Bayora"
LABEL component="Stateless Model Worker"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd -g 10002 modelworker && \
    useradd -u 10002 -g modelworker -s /bin/sh -d /app modelworker && \
    chown -R modelworker:modelworker /app

COPY --chown=modelworker:modelworker worker.py ./

USER modelworker

EXPOSE 8001

CMD ["uvicorn", "worker:app", "--host", "0.0.0.0", "--port", "8001"]
