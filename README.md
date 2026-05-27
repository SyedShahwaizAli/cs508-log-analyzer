# Secure Cloud Log Analyzer — CS-508

A web-based cloud log analysis tool powered by a **pure-Python MapReduce engine** with authentication, Neon DB persistence, and Railway deployment.

## Architecture

| Layer | Technology |
|---|---|
| Web Portal | Flask + Jinja2 |
| Parallel Processing | Custom MapReduce (ThreadPoolExecutor) |
| Security | Session-based IAM, `werkzeug` password hashing |
| Database | Neon DB (serverless PostgreSQL) |
| Deployment | Railway + GitHub CI/CD |

## MapReduce Pipeline

```
Raw Log Entries
    ↓ SPLIT — divide into 4 chunks
    ↓ MAP   — parse each chunk concurrently (ThreadPoolExecutor)
              emit (key, 1) pairs: http_error:404, hour:14, suspicious:...
    ↓ SHUFFLE — group by key
    ↓ REDUCE  — sum values → final counts
    ↓ Dashboard output
```

## Setup

1. Copy `.env.example` to `.env` and fill in values
2. Set `DATABASE_URL` from your [Neon DB](https://neon.tech) dashboard
3. Install: `pip install -r requirements.txt`
4. Run: `python app.py`
5. Login at `http://localhost:5000` with `admin` / `admin123`

## Deployment (Railway)

1. Push repo to GitHub
2. Connect Railway to the GitHub repo
3. Add environment variables in Railway dashboard:
   - `SECRET_KEY`
   - `DATABASE_URL` (from Neon DB)
4. Railway auto-deploys on every `git push`

## Secrets Management

- `SECRET_KEY` and `DATABASE_URL` are read via `os.environ` / `python-dotenv`
- `.env` is listed in `.gitignore` — never committed to version control
- No credentials appear in any source file

## Default Login

Username: `admin`  Password: `admin123`

*(Change via `ADMIN_PASSWORD_HASH` env var in production)*
