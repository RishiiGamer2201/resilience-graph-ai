# Single-container deploy: FastAPI serves the API + the built React SPA.
# Stage 1 — build the frontend
FROM node:20-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2 — python runtime (slim: no torch/pandas)
FROM python:3.10-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements-deploy.txt ./
RUN pip install --no-cache-dir -r requirements-deploy.txt

# app code + runtime artifacts (small)
COPY api ./api
COPY models/iforest_lanl.joblib models/next_technique_markov.pkl ./models/
COPY data/processed/mitre_attack/attack_lookups.pkl ./data/processed/mitre_attack/attack_lookups.pkl
# built SPA from stage 1
COPY --from=frontend /app/frontend/dist ./frontend/dist

EXPOSE 8000
# Hosts (Render/HF/Fly) inject $PORT; default 8000 locally.
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
