#!/bin/sh
set -e

mkdir -p /app/models

: "${MODEL_PKL_URL:?MODEL_PKL_URL is not set}"
: "${FEATURE_COLS_URL:?FEATURE_COLS_URL is not set}"

AUTH_HEADER=""
if [ -n "${HF_TOKEN:-}" ]; then
  AUTH_HEADER="Authorization: Bearer ${HF_TOKEN}"
fi

echo "Downloading model..."
curl -L -f ${AUTH_HEADER:+-H "$AUTH_HEADER"} "$MODEL_PKL_URL" -o /app/models/phishing_model.pkl

echo "Downloading feature columns..."
curl -L -f ${AUTH_HEADER:+-H "$AUTH_HEADER"} "$FEATURE_COLS_PKL_URL" -o /app/models/feature_columns.pkl

test -s /app/models/phishing_model.pkl
test -s /app/models/feature_columns.pkl

exec uvicorn server:app --host 0.0.0.0 --port "${PORT:-8000}"