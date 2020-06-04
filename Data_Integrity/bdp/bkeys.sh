#!/bin/bash

openssl req -new -x509 -newkey rsa:2048 -keyout bPrivatekey.key -pubkey -out Publickey.out -days 365 -nodes -sha256

sed -n 1,9p Publickey.out > bPublickey.key
sed -n 10,31p Publickey.out > bPublickey.cert

rm bPublickey.cert
rm Publickey.out

