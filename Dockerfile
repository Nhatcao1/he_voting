FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/opt/he-voting:/opt/he-voting/python
ENV HE_VOTING_RUNTIME=/data/runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libgomp1 \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/he-voting
COPY requirements.txt requirements-openfhe.txt ./
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements-openfhe.txt

COPY app ./app
COPY python ./python

EXPOSE 8000
CMD ["/opt/venv/bin/uvicorn", "app.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
