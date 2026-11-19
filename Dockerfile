# (c) Copyright 2019-2022, James Stevens ... see LICENSE for details
# Alternative license arrangements are possible, contact me for more information

FROM alpine:3.24
RUN apk update
RUN apk upgrade

COPY setup /usr/local/setup/
RUN /usr/local/setup/all

RUN rm -rf /run /tmp
RUN ln -s /dev/shm /run
RUN ln -s /dev/shm /tmp
RUN apk add nginx curl
RUN addgroup nginx daemon
RUN rmdir /var/lib/nginx/tmp
RUN ln -s /run/nginx /var/lib/nginx/tmp

RUN apk add postfix
COPY postfix/master.cf /etc/postfix/
COPY postfix/aliases /etc/postfix/
RUN newaliases
RUN ln -fns /run/templates/main.cf /etc/postfix/main.cf
RUN chown root:postfix /etc/postfix/
RUN chmod 750 /etc/postfix/
RUN ln -fns /opt/data/service/mailboxes /var/spool/mail

RUN apk add stunnel busybox-extras cyrus-sasl imap 
RUN apk add ldns-tools openssl
RUN apk add python3 py3-jinja2 py3-passlib py3-flask py3-filelock
RUN apk add py3-validators py3-idna py3-gunicorn py3-dnspython
RUN apk add php84-fpm php84-curl php84-iconv php84-dom php84-pdo_sqlite

RUN apk add jq ca-certificates-bundle


COPY etc /usr/local/etc/
RUN mkdir -p /usr/local/etc/uid /usr/local/nothing
RUN touch /usr/local/nothing/index.html
RUN chmod 750 /usr/local/etc/uid
RUN cp -a /etc/passwd /etc/shadow /etc/group /usr/local/etc/uid
RUN chmod 640 /usr/local/etc/uid/*
RUN chgrp -R service /usr/local/etc/uid
RUN cp -a /etc/passwd /etc/shadow /etc/group /run

RUN ln -fns /run/passwd /etc/passwd
RUN ln -fns /run/shadow /etc/shadow
RUN ln -fns /run/group /etc/group
RUN ln -s /opt/data/service/sasl2 /etc/sasl2

RUN rm -f /var/cache/apk/*

COPY config/default.conf /etc/nginx/http.d/default.conf
COPY config/inittab /etc/
COPY config/inetd.conf /etc/
COPY config/stunnel.conf /etc/stunnel/
COPY config/php-fpm.conf /etc/php84/php-fpm.conf
COPY config/www.conf /etc/php84/php-fpm.d/www.conf
COPY config/default.conf /etc/nginx/http.d/default.conf
COPY config/nginx.conf /etc/nginx/nginx.conf
RUN cp /etc/php84/php.ini etc/php84/php.orig
COPY config/php.ini /etc/php84/php.ini
COPY cron /usr/local/cron/
COPY cron/root /var/spool/cron/crontabs/root

COPY bin /usr/local/bin/
COPY htdocs /usr/local/htdocs/

COPY python /usr/local/python
RUN rm -rf /usr/local/python/.style.yapf /usr/local/python/pyproject.toml /usr/local/python/.ruff_cache
RUN python3 -m compileall /usr/local/python

COPY build.txt /usr/local/etc/build.txt
CMD [ "/usr/local/bin/run_init" ]
