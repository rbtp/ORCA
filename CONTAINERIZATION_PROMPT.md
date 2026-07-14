# ORCA Containerization — Full Implementation Spec

## Goal
Containerize the ORCA DFIR platform so it can be deployed to any machine running Docker.
The existing PostgreSQL container (`orca-postgres`) stays as-is.
We need containers for the backend (FastAPI + Node.js) and frontend (nginx).

## CRITICAL CONSTRAINTS
1. **Do NOT touch or recreate the existing `orca-postgres` container**
2. **PostgreSQL data must persist** — use named volume or existing container
3. **TLS is required** — backend runs HTTPS on port 8000
4. **Windows Velociraptor .exe stays** — it runs on remote endpoints, not the server
5. **After completing each step, update CLAUDE.md progress log**
6. **End your final message with exactly: TASK COMPLETE**

---

## Step 1: Read existing code first

Before writing anything, read these files to understand the project:
- `backend/main.py`
- `backend/requirements.txt` (if exists, else check imports in main.py)
- `frontend/package.json`
- `frontend/vite.config.js` (or vite.config.ts)

---

## Step 2: Extract hardcoded values to environment variables

The frontend has hardcoded `https://10.11.110.60:8000` throughout.
Find all occurrences and replace with `import.meta.env.VITE_API_URL`.

Create `frontend/.env.example`:
```
VITE_API_URL=https://10.11.110.60:8000
```

Create `frontend/.env`:
```
VITE_API_URL=https://10.11.110.60:8000
```

The backend has hardcoded DB connection. Find it and make it use env vars:
```
DATABASE_URL=postgresql://postgres:postgres@orca-postgres:5432/orca_db
```

Create `backend/.env.example`:
```
DATABASE_URL=postgresql://postgres:postgres@orca-postgres:5432/orca_db
JWT_SECRET=your-secret-here
TLS_CERT_PATH=/app/certs/orca.crt
TLS_KEY_PATH=/app/certs/orca.key
```

---

## Step 3: Backend Dockerfile

Create `backend/Dockerfile`:

```dockerfile
FROM python:3.9-slim

# Install Node.js for report_gen.js
RUN apt-get update && apt-get install -y \
    nodejs npm \
    clamav clamav-daemon \
    curl wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Node deps for report generation
COPY package*.json ./
RUN npm install 2>/dev/null || true

# Copy application
COPY . .

# ClamAV virus definitions directory
RUN mkdir -p /var/lib/clamav && freshclam || true

# Certs directory
RUN mkdir -p /app/certs

EXPOSE 8000

CMD ["python", "main.py"]
```

If `requirements.txt` doesn't exist, generate it by reading all imports in the backend Python files and creating it.

---

## Step 4: Frontend Dockerfile

Create `frontend/Dockerfile`:

```dockerfile
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]
```

Create `frontend/nginx.conf`:
```nginx
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass https://orca-backend:8000;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Step 5: docker-compose.yml

Create `docker-compose.yml` in the project root:

```yaml
version: '3.8'

services:
  orca-backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: orca-backend
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:postgres@orca-postgres:5432/orca_db
      - JWT_SECRET=${JWT_SECRET:-orca-secret-change-me}
      - TLS_CERT_PATH=/app/certs/orca.crt
      - TLS_KEY_PATH=/app/certs/orca.key
    volumes:
      - ./backend/orca.crt:/app/certs/orca.crt:ro
      - ./backend/orca.key:/app/certs/orca.key:ro
      - ./backend/bin:/app/bin:ro
      - orca-evidence:/app/evidence
    networks:
      - orca-net
    depends_on:
      - orca-postgres

  orca-frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
      args:
        - VITE_API_URL=${VITE_API_URL:-https://localhost:8000}
    container_name: orca-frontend
    restart: unless-stopped
    ports:
      - "80:80"
    networks:
      - orca-net
    depends_on:
      - orca-backend

  orca-postgres:
    image: postgres:15
    container_name: orca-postgres
    restart: unless-stopped
    environment:
      - POSTGRES_DB=orca_db
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    volumes:
      - orca-postgres-data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
      - "5433:5432"
    networks:
      - orca-net

networks:
  orca-net:
    driver: bridge

volumes:
  orca-postgres-data:
  orca-evidence:
```

**IMPORTANT:** The existing `orca-postgres` container must join the `orca-net` network OR the compose file must reference it as an external container. Check if the existing container is already running and handle accordingly by using `external: true` for the network if needed.

---

## Step 6: Environment file

Create `.env` in project root:
```
JWT_SECRET=orca-secret-change-me
VITE_API_URL=https://10.11.110.60:8000
```

Create `.env.example`:
```
JWT_SECRET=change-this-to-a-random-secret
VITE_API_URL=https://YOUR_SERVER_IP:8000
```

---

## Step 7: Startup scripts

Create `start.sh` (Linux/Mac):
```bash
#!/bin/bash
echo "[ORCA] Starting..."
docker compose up -d
echo "[ORCA] Started. Frontend: http://localhost, Backend: https://localhost:8000"
```

Create `start.bat` (Windows):
```batch
@echo off
echo [ORCA] Starting...
docker compose up -d
echo [ORCA] Started.
echo Frontend: http://localhost
echo Backend: https://localhost:8000
pause
```

Create `stop.bat`:
```batch
@echo off
docker compose down
echo [ORCA] Stopped.
pause
```

Create `logs.bat`:
```batch
@echo off
docker compose logs -f
```

---

## Step 8: Handle existing orca-postgres container

The user already has a running `orca-postgres` container with data.
Two scenarios — handle both:

**Scenario A: Fresh deployment to new machine**
The compose file creates a new postgres container. Include a note in README.

**Scenario B: Existing orca-postgres on same machine**
Add this to docker-compose.yml to connect to existing container:
```yaml
# If orca-postgres is already running as a standalone container,
# connect it to the orca-net network:
# docker network connect orca-net orca-postgres
```

Document this in README.md.

---

## Step 9: README.md

Create `DEPLOY.md`:
```markdown
# ORCA Deployment Guide

## Fresh Install (New Machine)

1. Install Docker Desktop
2. Copy the ORCA folder to the new machine
3. Copy your TLS cert: ensure `backend/orca.crt` and `backend/orca.key` exist
4. Edit `.env` — set JWT_SECRET and VITE_API_URL to your server IP
5. Run: `start.bat`
6. Open browser: `http://YOUR_SERVER_IP`

## Migrating Existing Installation

If you have an existing orca-postgres container with data:

1. Export existing data:
   `docker exec orca-postgres pg_dump -U postgres orca_db > orca_backup.sql`

2. Start new stack:
   `docker compose up -d`

3. Import data:
   `docker exec -i orca-postgres-new psql -U postgres orca_db < orca_backup.sql`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| JWT_SECRET | Secret for JWT signing | orca-secret-change-me |
| VITE_API_URL | Backend URL for frontend | https://localhost:8000 |
| DATABASE_URL | PostgreSQL connection string | postgresql://postgres:postgres@orca-postgres:5432/orca_db |

## Ports

| Service | Port |
|---------|------|
| Frontend | 80 |
| Backend API | 8000 |
| PostgreSQL | 5432 |

## TLS Certificate

The backend requires a TLS certificate. The existing self-signed cert is used by default.
To generate a new self-signed cert:
```
openssl req -x509 -newkey rsa:4096 -keyout backend/orca.key -out backend/orca.crt -days 365 -nodes -subj "/CN=orca"
```
```

---

## Implementation Order

1. Read existing files (main.py, package.json, vite config)
2. Find and replace all hardcoded IPs in frontend with VITE_API_URL
3. Find and replace hardcoded DB connection in backend with env var
4. Create backend/Dockerfile
5. Create frontend/Dockerfile + nginx.conf
6. Create docker-compose.yml
7. Create .env and .env.example
8. Create start.bat, stop.bat, logs.bat
9. Create DEPLOY.md
10. Update CLAUDE.md progress log after each step
11. Attempt `docker compose build` and fix any errors
12. Report what worked and what needs manual verification

## After Each Step

Update `CLAUDE.md`:
- Mark completed steps with [x]
- Update "Last Completed Step"
- Update "Next Step"
- Log any decisions made

## Final Message

When all steps are complete, output:
```
## DEPLOYMENT SUMMARY
- Files created: [list]
- Files modified: [list]  
- Manual steps required: [list anything that needs human action]
- To deploy: run start.bat
```

Then write exactly: TASK COMPLETE
