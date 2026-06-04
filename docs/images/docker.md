# LogGuard AI - Docker Setup

## Services

Docker Compose starts:

- PostgreSQL
- Redis
- FastAPI backend
- Celery worker
- Next.js frontend

## Environment

Create a Docker environment file:

```powershell
Copy-Item .env.docker.example .env.docker