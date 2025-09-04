#!/usr/bin/env bash
set -e

IMAGE_NAME="${IMAGE_NAME:-app-local}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
APP_EXTERNAL_PORT="${APP_EXTERNAL_PORT:-8080}"
APP_INTERNAL_PORT="${APP_INTERNAL_PORT:-80}"
APP_HEALTH_PATH="${APP_HEALTH_PATH:-/login.php}"
CONTAINER_NAME="${CONTAINER_NAME:-dvwa_app}"

docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

if ! docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" >/dev/null 2>&1; then
  echo "Image ${IMAGE_NAME}:${IMAGE_TAG} not found"
  exit 1
fi

docker run -d --name "${CONTAINER_NAME}" \
  -p "${APP_EXTERNAL_PORT}:${APP_INTERNAL_PORT}" \
  --restart unless-stopped \
  "${IMAGE_NAME}:${IMAGE_TAG}"

# Health check
i=0
while [ $i -lt 60 ]; do
  code="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${APP_EXTERNAL_PORT}${APP_HEALTH_PATH}")"
  if [ "$code" = "200" ]; then
    echo "App is healthy"
    exit 0
  fi
  i=$((i+1))
  echo "Waiting ($i/60) code=$code"
  sleep 2
done

echo "Health check failed"
exit 1
