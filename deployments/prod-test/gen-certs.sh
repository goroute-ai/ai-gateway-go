#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-.tmp/prod-test-certs}"
mkdir -p "$OUT_DIR"

if [[ -f "$OUT_DIR/ca.crt" && -f "$OUT_DIR/server.crt" && -f "$OUT_DIR/server.key" ]]; then
  echo "==> Reusing existing ephemeral prod-test TLS certs in $OUT_DIR"
  exit 0
fi

echo "==> Generating ephemeral prod-test Root CA and SAN server certificate in $OUT_DIR..."

cat >"$OUT_DIR/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = GoRoute Prod-Test Ephemeral Root CA

[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

cat >"$OUT_DIR/server.cnf" <<'EOF'
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = gateway.prod.test

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = gateway.prod.test
DNS.2 = auth.prod.test
DNS.3 = postgres
DNS.4 = redis
DNS.5 = localhost
IP.1 = 127.0.0.1
IP.2 = 172.30.10.200
EOF

openssl genrsa -out "$OUT_DIR/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$OUT_DIR/ca.key" -sha256 -days 2 \
  -out "$OUT_DIR/ca.crt" -config "$OUT_DIR/ca.cnf" 2>/dev/null

openssl genrsa -out "$OUT_DIR/server.key" 2048 2>/dev/null
openssl req -new -key "$OUT_DIR/server.key" -out "$OUT_DIR/server.csr" \
  -config "$OUT_DIR/server.cnf" 2>/dev/null
openssl x509 -req -in "$OUT_DIR/server.csr" -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" \
  -CAcreateserial -out "$OUT_DIR/server.crt" -days 2 -sha256 \
  -extfile "$OUT_DIR/server.cnf" -extensions v3_req 2>/dev/null

chmod 644 "$OUT_DIR/ca.crt" "$OUT_DIR/server.crt" "$OUT_DIR/server.key"
rm -f "$OUT_DIR/ca.cnf" "$OUT_DIR/server.cnf" "$OUT_DIR/server.csr" "$OUT_DIR/ca.srl"
echo "==> Ephemeral TLS certificates ready."
