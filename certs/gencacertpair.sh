#!/bin/bash
openssl genpkey -genparam -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve \
    -out key-params.pem

openssl req -nodes -newkey ec:key-params.pem \
    -keyout ca-key.pem \
    -out ca-req.pem

openssl x509 -days 3650 \
    -in ca-req.pem \
    -out ca-cert.pem -req \
    -signkey ca-key.pem

openssl x509 -in ca-cert.pem -outform der -out ca-cert.crt

echo ====== CLIENT =======

openssl req -nodes -newkey ec:key-params.pem \
    -keyout client-key.pem \
    -out client-req.pem

openssl x509 -days 3650 \
    -in client-req.pem \
    -out client-cert.pem -req \
    -CA ca-cert.pem \
    -CAkey ca-key.pem \
    -CAcreateserial

openssl x509 -in client-cert.pem -outform der -out client-cert.crt
cat client-key.pem client-cert.pem > client-keypair.pem

echo ====== SERVER =======

echo -n "Enter domain name to include in the certificate: "
read CERT_CN

echo -n "Enter the IP to include in the certificate: "
read CERT_IP

cat > server-cert-ext.cnf << EOF
basicConstraints = CA:FALSE
nsCertType = server
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${CERT_CN}
DNS.2 = localhost
IP = ${CERT_IP}
EOF


openssl req -nodes -newkey ec:key-params.pem \
    -keyout server-key.pem \
    -out server-req.pem

openssl x509 -days 3650 \
    -in server-req.pem \
    -out server-cert.pem -req \
    -extfile server-cert-ext.cnf \
    -CA ca-cert.pem \
    -CAkey ca-key.pem \
    -CAcreateserial

openssl x509 -in server-cert.pem -outform der -out server-cert.crt
cat server-key.pem server-cert.pem > server-keypair.pem