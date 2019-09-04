set -e

openssl genrsa -out prikey.pem 2048
openssl rsa -in prikey.pem -pubout -out pubkey.pem