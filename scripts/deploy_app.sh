#!/usr/bin/env bash
set -eu  

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

sleep 2

TARGET_URL="http://127.0.0.1:${APP_EXTERNAL_PORT}${APP_HEALTH_PATH}"
echo ">>> Health probe: ${TARGET_URL}"

i=0; max=60
while [ $i -lt $max ]; do
  code="$(curl -sS -o /dev/null -w '%{http_code}' \
            --fail --retry 5 --retry-connrefused --retry-delay 1 \
            --connect-timeout 5 --max-time 10 \
            -H 'Connection: close' \
            "${TARGET_URL}" || echo 000)"

  if [ "$code" = "200" ] || [ "$code" = "302" ]; then 
    echo "App is healthy (HTTP $code)"
    exit 0
  fi

  i=$((i+1))
  echo "Waiting (${i}/${max}) code=${code}"
  sleep 2
done

echo "Health check failed after ${max} attempts"
docker logs --tail 80 "${CONTAINER_NAME}" || true
exit 1
