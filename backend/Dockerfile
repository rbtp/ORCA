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
RUN pip install --no-cache-dir -r requirements.txt

COPY package*.json ./
RUN npm install

COPY . .

RUN mkdir -p /app/certs /var/lib/clamav

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "main.py"]
