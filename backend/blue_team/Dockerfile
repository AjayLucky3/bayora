FROM python:3.11-slim

LABEL maintainer="Ajay Doma <domaajay187@gmail.com>"
LABEL project="Bayora"
LABEL component="Blue Team Zero-Knowledge Scorer"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd -g 10003 bluescorer && \
    useradd -u 10003 -g bluescorer -s /bin/sh -d /app bluescorer && \
    chown -R bluescorer:bluescorer /app

COPY --chown=bluescorer:bluescorer scorer.py ./

USER bluescorer

EXPOSE 8002

CMD ["uvicorn", "scorer:app", "--host", "0.0.0.0", "--port", "8002"]
