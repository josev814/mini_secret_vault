#!/bin/sh
set -e

# Install PHP dependencies via Composer
composer require
composer install --no-interaction --prefer-dist --working-dir=/var/www/html

# Run DB init
php -f /var/www/html/private/scripts/init_db.php

# Start Apache in foreground
apache2-foreground