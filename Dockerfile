FROM php:8.3-apache

RUN docker-php-ext-install pdo pdo_mysql

WORKDIR /var/www/html

COPY . /var/www/html

RUN sed -i 's/\/html/\/html\/public/' /etc/apache2/sites-enabled/000-default.conf \
    && chown -R www-data:www-data /var/www/html \
    && a2enmod rewrite

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
EXPOSE 80
CMD ["apache2-foreground"]