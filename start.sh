#!/bin/sh
set -e

APP_DIR="/app"
MODEL_DIR="$APP_DIR/models"
ZIP_PATH="$APP_DIR/models.zip"
TMP_DIR="$APP_DIR/_models_tmp"

mkdir -p "$MODEL_DIR"

# If we already have .pkl files in /app/models, don’t download again
if ls "$MODEL_DIR"/*.pkl >/dev/null 2>&1; then
  echo "Models already present in $MODEL_DIR, skipping download."
  exec uvicorn server:app --host 0.0.0.0 --port "${PORT:-8000}"
fi

if [ -z "${MODELS_ZIP_URL:-}" ]; then
  echo "ERROR: MODELS_ZIP_URL env var is not set"
  exit 1
fi

echo "Downloading models zip..."
rm -f "$ZIP_PATH"
curl -L -f "$MODELS_ZIP_URL" -o "$ZIP_PATH"

echo "Extracting to temp..."
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
unzip -o "$ZIP_PATH" -d "$TMP_DIR" >/dev/null

# Find the first directory named 'models' inside the extracted tree
FOUND_MODELS_DIR="$(find "$TMP_DIR" -type d -name models | head -n 1 || true)"

if [ -z "$FOUND_MODELS_DIR" ]; then
  echo "ERROR: Could not find a 'models' directory inside the zip."
  echo "Top-level extracted contents:"
  find "$TMP_DIR" -maxdepth 3 -mindepth 1 -print
  exit 1
fi

echo "Found nested models folder at: $FOUND_MODELS_DIR"
echo "Installing models to $MODEL_DIR ..."

rm -rf "$MODEL_DIR"
mkdir -p "$MODEL_DIR"

# Copy contents of the found models dir into /app/models
cp -R "$FOUND_MODELS_DIR"/. "$MODEL_DIR"/

# Sanity check
if ! ls "$MODEL_DIR"/*.pkl >/dev/null 2>&1; then
  echo "ERROR: No .pkl files found after install. Contents of $MODEL_DIR:"
  ls -la "$MODEL_DIR"
  exit 1
fi

echo "Models ready."
exec uvicorn server:app --host 0.0.0.0 --port "${PORT:-8000}"