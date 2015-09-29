#!/bin/sh

MSTR="../../mstring/mstring"

[ -x $MSTR ] || make -C ../../mstring

$MSTR http_hdr \
 "Host:" \
 "X-Forwarded-For:" \
 "Referer:" \
 "Content-Type:" \
 "Accept:" \
 "User-Agent:" \
 "Content-Encoding:" \
 "Transfer-Encoding:" \
 "Content-Length:" \
 "Cookie:" \
 "X-Session-Type:" \
 "Server:" \
 "Origin:" >ndpi_http_hdr.c.inc
