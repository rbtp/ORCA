# ORCA Deployment Guide

## Fresh Install (New Machine)

1. Install Docker Desktop
2. Copy the ORCA folder to the new machine
3. Ensure `backend/orca.crt` and `backend/orca.key` exist (TLS cert/key)
4. Edit `.env` — set `JWT_SECRET` and `VITE_API_URL` to your server's IP
5. Run: `start.bat`
6. Open browser: `http://YOUR_SERVER_IP`

## Existing Installation (Same Machine)

If you already have a running `orca-postgres` container with data:

1. Export existing data:
   ```
   docker exec orca-postgres pg_dump -U postgres orca_db > orca_backup.sql
   ```

2. Create the shared network and connect the existing postgres container:
   ```
   docker network create orca-net
   docker network connect orca-net orca-postgres
   ```

3. Start only the backend and frontend (skip postgres):
   ```
   docker compose up -d orca-backend orca-frontend
   ```

## Migrating to a New Machine

1. Export data from old machine:
   ```
   docker exec orca-postgres pg_dump -U postgres orca_db > orca_backup.sql
   ```

2. Start full stack on new machine:
   ```
   docker compose up -d
   ```

3. Import data:
   ```
   docker exec -i orca-postgres psql -U postgres orca_db < orca_backup.sql
   ```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | Secret for JWT token signing | `orca-secret-change-me` |
| `VITE_API_URL` | Backend HTTPS URL (used by frontend) | `https://localhost:8000` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://postgres:postgres@orca-postgres:5432/orca_db` |
| `TLS_CERT_PATH` | Path to TLS certificate inside container | `/app/certs/orca.crt` |
| `TLS_KEY_PATH` | Path to TLS key inside container | `/app/certs/orca.key` |

## Ports

| Service | Port |
|---------|------|
| Frontend (nginx) | 80 |
| Backend API (HTTPS) | 8000 |
| PostgreSQL | 5432 / 5433 |

## TLS Certificate

The backend requires a TLS certificate. The self-signed cert in `backend/` is used by default via volume mount.

To generate a new self-signed cert:
```
openssl req -x509 -newkey rsa:4096 -keyout backend/orca.key -out backend/orca.crt -days 365 -nodes -subj "/CN=orca"
```

## Updating VITE_API_URL for a New Server

1. Edit `.env` in the project root:
   ```
   VITE_API_URL=https://NEW_SERVER_IP:8000
   ```
2. Rebuild the frontend container:
   ```
   docker compose build orca-frontend
   docker compose up -d orca-frontend
   ```

Note: `VITE_API_URL` is baked into the frontend at build time. Any change requires a rebuild.
