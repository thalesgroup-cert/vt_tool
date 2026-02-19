FROM python:3.11-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY

ENV https_proxy ${HTTPS_PROXY:-$HTTP_PROXY}
ENV http_proxy ${HTTP_PROXY:-$HTTPS_PROXY}

RUN apt-get update && \
    apt-get install -y git curl unzip && \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/thalesgroup-cert/vt_tool.git /opt/vt_tool && \
    pip install --no-cache-dir -r /opt/vt_tool/requirements.txt && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY webapp/ /app/

EXPOSE 8080
CMD ["python", "app.py"]
