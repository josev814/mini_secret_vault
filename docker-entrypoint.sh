#!/bin/sh
set -e
# Run DB init
php -f /var/www/html/private/scripts/init_db.php

# Start Apache in foreground
apache2-foreground