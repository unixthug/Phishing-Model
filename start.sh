#!/bin/sh
set -e
: "${MODEL_PKL_URL:?MODEL_PKL_URL is not set}"
: "${FEATURE_COLS_URL:?FEATURE_COLS_URL is not set}"
AUTH_HEADER=""
if [ -n "${HF_TOKEN:-}" ]; then
  AUTH_HEADER="Authorization: Bearer ${HF_TOKEN}"
fi
echo "Downloading model..."
curl -L -f --retry 3 --retry-delay 2 ${AUTH_HEADER:+-H "$AUTH_HEADER"} "$MODEL_PKL_URL" -o /app/lbgm_model.pkl
echo "Downloading feature columns..."
curl -L -f --retry 3 --retry-delay 2 ${AUTH_HEADER:+-H "$AUTH_HEADER"} "$FEATURE_COLS_URL" -o /app/feature_names.pkl
test -s /app/lbgm_model.pkl
test -s /app/feature_names.pkl
exec gunicorn server:app --bind 0.0.0.0:"${PORT:-8000}" --workers 2 --timeout 120
