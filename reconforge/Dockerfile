FROM node:20-slim AS frontend-build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --production=false 2>/dev/null || true
COPY frontend/ .
RUN npx vite build 2>/dev/null || mkdir -p dist

FROM python:3.11-slim

LABEL maintainer="ReconForge"
LABEL description="ReconForge - Universal OSINT & Static Analysis Engine"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    unzip \
    whois \
    dnsutils \
    smbclient \
    default-jre-headless \
    binutils \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sL "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip" -o /tmp/jadx.zip \
    && unzip /tmp/jadx.zip -d /opt/jadx \
    && rm /tmp/jadx.zip \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/
COPY --from=frontend-build /frontend/dist frontend/dist/

RUN mkdir -p data/uploads data/reports data/decompiled data/screenshots

ENV RF_HOST=0.0.0.0 \
    RF_PORT=8800 \
    RF_DEBUG=false

EXPOSE 8800

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8800"]
