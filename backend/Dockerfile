FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    nodejs npm \
    clamav clamav-daemon \
    openssl \
    curl wget \
    libreoffice \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    CAPA_VER=$(python -c "import importlib.metadata; print(importlib.metadata.version('flare-capa'))") && \
    SITE_PKGS=$(python -c "import site; print(site.getsitepackages()[0])") && \
    wget -q "https://github.com/mandiant/capa-rules/archive/refs/tags/v${CAPA_VER}.tar.gz" \
         -O /tmp/capa-rules.tar.gz && \
    tar -xzf /tmp/capa-rules.tar.gz -C /tmp && \
    mv /tmp/capa-rules-${CAPA_VER} "${SITE_PKGS}/rules" && \
    rm /tmp/capa-rules.tar.gz && \
    mkdir -p "${SITE_PKGS}/sigs"

COPY package*.json ./
RUN npm install

COPY . .

RUN mkdir -p /app/certs /var/lib/clamav

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Drop to non-root user; pre-create writable directories with correct ownership
RUN useradd -r -u 1000 -g root -s /bin/false orca && \
    mkdir -p /app/certs /app/evidence /app/.cache /var/lib/clamav /tmp/orca_behavioral && \
    chown -R orca:root /app /var/lib/clamav /tmp/orca_behavioral /entrypoint.sh && \
    chmod -R g+w /app /var/lib/clamav /tmp/orca_behavioral

# Volatility3 resolves its cache via XDG_CACHE_HOME or expanduser("~").
# The orca system user has no home dir, so point XDG_CACHE_HOME at a
# pre-created path under /app that orca already owns.
ENV XDG_CACHE_HOME=/app/.cache

USER orca

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "main.py"]
