openssl req -new -x509 -newkey rsa:4096 -sha256 -nodes -keyout ./test.key -days 3560 -out ./test.cer -config ./test.cnf
openssl pkcs12 -export -in ./test.cer -inkey ./test.key -out test.pfx