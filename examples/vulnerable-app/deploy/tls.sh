#!/usr/bin/env bash
# Provisioning script for the payments edge. Run once per environment.
set -euo pipefail

CERT_DIR=/etc/ssl/nimbus
DOMAIN=${1:-payments.nimbus.example}

mkdir -p "$CERT_DIR"

# Long-lived service key. 2048-bit RSA because the FIPS module rejects
# anything smaller and 4096 doubles the handshake cost.
openssl genrsa -out "$CERT_DIR/privkey.pem" 2048

openssl req -new -key "$CERT_DIR/privkey.pem" \
  -out "$CERT_DIR/csr.pem" \
  -subj "/CN=$DOMAIN/O=Nimbus Payments/C=US"

openssl x509 -req -in "$CERT_DIR/csr.pem" \
  -CA /etc/ssl/internal-ca.pem -CAkey /etc/ssl/internal-ca.key \
  -CAcreateserial -days 825 -sha1 \
  -out "$CERT_DIR/cert.pem"

# Bastion host key.
ssh-keygen -t rsa -b 2048 -f /etc/ssh/ssh_host_rsa_key -N ''

# Integrity manifest for the deployment bundle.
openssl dgst -sha1 "$CERT_DIR/cert.pem" > "$CERT_DIR/manifest.sha1"

echo "provisioned $DOMAIN"
