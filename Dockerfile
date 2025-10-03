# (c) Copyright 2019-2022, James Stevens ... see LICENSE for details
# Alternative license arrangements are possible, contact me for more information

FROM alpine:3.22
RUN apk update
RUN apk upgrade

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
RUN ln -fns /opt/data/postfix/mailboxes /var/spool/mail

RUN apk add stunnel busybox-extras cyrus-sasl imap 
RUN apk add ldns-tools openssl
RUN apk add python3 py3-jinja2 py3-passlib py3-flask py3-filelock py3-validators
RUN apk add php84-fpm php84-curl php84-iconv php84-dom

COPY etc /usr/local/etc/
RUN mkdir -p /opt/data/etc
RUN cp -a /etc/passwd /etc/shadow /etc/group /usr/local/etc
RUN cp -a /etc/passwd /etc/shadow /etc/group /opt/data/etc
RUN ln -fns /opt/data/etc/passwd /etc/passwd
RUN ln -fns /opt/data/etc/shadow /etc/shadow
RUN ln -fns /opt/data/etc/group /etc/group

RUN ln -s /opt/data/sasl2 /etc/sasl2

COPY config/default.conf /etc/nginx/http.d/default.conf
COPY config/inittab /etc/
COPY config/inetd.conf /etc/
COPY config/stunnel.conf /etc/stunnel/
COPY config/php-fpm.conf /etc/php84/php-fpm.conf
COPY config/www.conf /etc/php84/php-fpm.d/www.conf
COPY config/default.conf /etc/nginx/http.d/default.conf
COPY config/nginx.conf /etc/nginx/nginx.conf
COPY config/php.ini /etc/php84/php.ini
COPY cron/every_hour /etc/periodic/hourly/

RUN chown -R nobody: /usr/local/etc/data
RUN chmod 700 /usr/local/etc/data

COPY bin /usr/local/bin/
COPY htdocs /usr/local/htdocs/

COPY python /usr/local/python
RUN python3 -m compileall /usr/local/python

CMD [ "/usr/local/bin/run_init" ]
