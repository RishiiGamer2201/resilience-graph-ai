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
COPY src ./src
COPY configs ./configs
# ae_lanl.npz IS the shipped detector (NumPy inference, ~5 KB). Without it the
# container silently falls back to the IsolationForest, which catches far fewer
# red-team events at the 1% false-positive point — a deployed image that scores
# differently from the one we measured is worse than one that fails loudly.
COPY models/ae_lanl.npz models/iforest_lanl.joblib models/next_technique_markov.pkl ./models/
COPY data/processed/mitre_attack/attack_lookups.pkl ./data/processed/mitre_attack/attack_lookups.pkl
COPY data/processed/engine2/technique_embeddings.pkl ./data/processed/engine2/technique_embeddings.pkl
COPY data/processed/evidence/index.json.gz ./data/processed/evidence/index.json.gz
COPY data/demo/scenarios ./data/demo/scenarios
COPY data/manual ./data/manual
# canonical metrics — the scoreboard reads these, it never hard-codes them
COPY reports/metrics.json ./reports/metrics.json
# built SPA from stage 1
COPY --from=frontend /app/frontend/dist ./frontend/dist

EXPOSE 8000
# Hosts (Render/HF/Fly) inject $PORT; default 8000 locally.
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
