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
COPY postfix/main.cf /etc/postfix
COPY postfix/master.cf /etc/postfix
COPY postfix/aliases /etc/postfix
RUN postalias /etc/postfix/aliases

RUN apk add stunnel busybox-extras cyrus-sasl imap 
RUN apk add ldns-tools openssl
RUN apk add python3
RUN apk add php84-fpm php84-curl php84-iconv php84-dom

RUN mkdir -p /usr/local/etc
RUN cp -a /etc/passwd /usr/local/etc
RUN cp -a /etc/shadow /usr/local/etc
RUN mkdir -p /opt/data/etc
RUN cp -a /etc/passwd /opt/data/etc
RUN cp -a /etc/shadow /opt/data/etc
RUN ln -fns /opt/data/etc/passwd /etc/passwd
RUN ln -fns /opt/data/etc/shadow /etc/shadow

RUN ln -s /opt/data/sasl2 /etc/sasl2

COPY config/default.conf /etc/nginx/http.d/default.conf
COPY config/inittab /etc/
COPY config/inetd.conf /etc/
COPY config/stunnel.conf /etc/stunnel/
COPY config/php-fpm.conf /etc/php84/php-fpm.conf
COPY config/www.conf /etc/php84/php-fpm.d/www.conf
COPY config/default.conf /etc/nginx/http.d/default.conf
COPY config/nginx.conf /etc/nginx/nginx.conf
COPY config/data /usr/local/etc/data/
COPY config/php.ini /etc/php84/php.ini

RUN chown -R nobody: /usr/local/etc/data
RUN chmod 700 /usr/local/etc/data

COPY bin /usr/local/bin/
COPY htdocs /usr/local/htdocs/

COPY python /usr/local/python
RUN python3 -m compileall /usr/local/python

CMD [ "/usr/local/bin/run_init" ]
