FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping tcpdump procps \
    && rm -rf /var/lib/apt/lists/*

ARG CODICE=sconosciuto
LABEL it.tirocinio.codice=$CODICE

WORKDIR /opt/banco
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY model/ model/
COPY common/ common/
COPY app/ app/
COPY sensor/ sensor/
COPY ids/ ids/
COPY observer/ observer/
COPY orchestrator/ orchestrator/
COPY analysis/ analysis/

ENV PYTHONPATH=/opt/banco PYTHONUNBUFFERED=1
RUN mkdir -p /dati/local /dati/bordo /dati/omniscient

CMD ["/bin/sh"]
