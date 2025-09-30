# (c) Copyright 2019-2022, James Stevens ... see LICENSE for details
# Alternative license arrangements are possible, contact me for more information

FROM alpine:3.22
RUN apk update
RUN apk upgrade

RUN rm -rf /run
RUN ln -s /dev/shm /run
RUN apk add nginx curl
RUN addgroup nginx daemon

RUN apk add postfix
COPY postfix/main.cf /etc/postfix
COPY postfix/master.cf /etc/postfix
COPY postfix/aliases /etc/postfix
RUN postalias /etc/postfix/aliases

RUN apk add stunnel busybox-extras cyrus-sasl imap 
RUN apk add ldns-tools openssl
RUN apk add python3

RUN mkdir -p /etc/sasl2
RUN ln -s /opt/data/sasl2/sasldb2 /etc/sasl2/sasldb2

COPY config/inittab /etc/
COPY config/inetd.conf /etc/
COPY config/stunnel.conf /etc/stunnel/

RUN mkdir /usr/local/etc
COPY config/passwd /usr/local/etc
COPY config/shadow /usr/local/etc

RUN ln -fns /opt/data/etc/passwd /etc/passwd
RUN ln -fns /opt/data/etc/shadow /etc/shadow

COPY bin /usr/local/bin/
COPY htdocs /usr/local/htdocs/

COPY python /usr/local/python
RUN python3 -m compileall /usr/local/python

CMD [ "/usr/local/bin/run_init" ]
