#!/bin/sh

openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=proxy2 CA"
openssl genrsa -out cert.key 2048
mkdir certs/
