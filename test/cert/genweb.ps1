openssl genrsa -out privkey.pem 2048
openssl req -new -x509 -key privkey.pem -out fullchain.pem -days 3560 -config ./test.cnf