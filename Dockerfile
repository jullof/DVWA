FROM php:8.2-apache

LABEL org.opencontainers.image.source="https://github.com/digininja/DVWA"
LABEL org.opencontainers.image.description="DVWA pre-built image."
LABEL org.opencontainers.image.licenses="gpl-3.0"

WORKDIR /var/www/html

RUN set -eux; \
    apt-get update; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get install -y --no-install-recommends \
      zlib1g-dev libpng-dev libjpeg-dev libfreetype6-dev \
      git iputils-ping unzip; \
    rm -rf /var/lib/apt/lists/*; \
    docker-php-ext-configure gd --with-jpeg --with-freetype; \
    a2enmod rewrite; \
    docker-php-ext-install -j"$(nproc)" gd mysqli pdo pdo_mysql

COPY --from=composer:latest /usr/bin/composer /usr/local/bin/composer

COPY --chown=www-data:www-data . . 


COPY --chown=www-data:www-data config/config.inc.php.dist config/config.inc.php

RUN set -eux; \
    cd /var/www/html/vulnerabilities/api; \
    composer install --no-dev --prefer-dist --no-interaction

RUN set -eux; \
    mkdir -p \
      /var/www/html/hackable/uploads \
      /var/www/html/external/phpids/0.6/lib/IDS/tmp/cache; \
    chown -R www-data:www-data \
      /var/www/html \
      /var/www/html/hackable \
      /var/www/html/external/phpids/0.6/lib/IDS/tmp/cache

EXPOSE 80

