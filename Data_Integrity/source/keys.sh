#!/bin/bash

openssl req -new -x509 -newkey rsa:2048 -keyout Privatekey.key -pubkey -out Publickey.out -days 365 -nodes -sha256

sed -n 1,9p Publickey.out > Publickey.key
sed -n 10,31p Publickey.out > Publickey.cert

rm Publickey.cert
rm Publickey.out

