#!/usr/bin/env bash
set -e
NET=app-net
APP=app-under-test
DB=dvwa-db

docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$DB" >/dev/null 2>&1 || true
docker run -d --name "$DB" --network "$NET" \
  -e MYSQL_ROOT_PASSWORD='p@ssw0rd' -e MYSQL_DATABASE='dvwa' \
  -e MYSQL_USER='dvwa' -e MYSQL_PASSWORD='p@ssw0rd' \
  mariadb:10.6 --default-authentication-plugin=mysql_native_password

until docker exec "$DB" mysql -udvwa -p'p@ssw0rd' -e 'SELECT 1' dvwa >/dev/null 2>&1; do
  sleep 2
done

docker rm -f "$APP" >/dev/null 2>&1 || true
docker run -d --name "$APP" --network "$NET" -p 8080:80 \
  -e DB_SERVER="$DB" -e MYSQL_DATABASE='dvwa' -e MYSQL_USER='dvwa' -e MYSQL_PASSWORD='p@ssw0rd' \
  "${IMAGE_NAME}:${IMAGE_TAG}"
