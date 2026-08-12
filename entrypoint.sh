#!/bin/sh

DOMAIN="${CHECK_DOMAIN:-check.quip.network}"
CERT_DIR="/etc/ssl"
CERT_FILE="${CERT_DIR}/${DOMAIN}.crt"
KEY_FILE="${CERT_DIR}/${DOMAIN}.key"

# --- Restore the system trust store if the volume shadowed it ---
# /etc/ssl is the app's persistent volume. Depending on how it is mounted it can
# come up empty, taking the CA bundle with it. Go verifies /probe's tls, rpc,
# telemetry and dashboard checks against the system pool, so a missing bundle
# turns all four into "x509: certificate signed by unknown authority" while the
# raw-TCP checks keep passing — a confusing half-failure. Restore, never
# overwrite, so an issued cert in the volume is untouched.
if [ ! -f "${CERT_DIR}/certs/ca-certificates.crt" ]; then
    echo "[entrypoint] CA bundle missing from ${CERT_DIR}, restoring from image defaults."
    mkdir -p "${CERT_DIR}/certs"
    cp /opt/ssl-defaults/certs/ca-certificates.crt "${CERT_DIR}/certs/ca-certificates.crt"
fi
if [ ! -f "${CERT_DIR}/cert.pem" ]; then
    cp /opt/ssl-defaults/cert.pem "${CERT_DIR}/cert.pem"
fi

# --- TLS Certificate via dnsimple-certifier ---
if [ -f "${CERT_FILE}" ]; then
    echo "[entrypoint] Certificate already exists, attempting renewal..."
    if certifier renew --domain "${DOMAIN}" --cert "${CERT_FILE}" --out "${CERT_DIR}/"; then
        echo "[entrypoint] Renewal check complete."
    else
        echo "[entrypoint] Renewal skipped or failed, using existing cert."
    fi
else
    echo "[entrypoint] Requesting certificate for ${DOMAIN}..."
    mkdir -p "${CERT_DIR}"
    if certifier issue --domain "${DOMAIN}" --out "${CERT_DIR}/"; then
        echo "[entrypoint] Certificate obtained."
    else
        echo "[entrypoint] ERROR: cert issuance failed."
        echo "[entrypoint] WARNING: No cert found, starting without TLS."
    fi
fi

# --- Start nginx (if cert exists) ---
if [ -f "${CERT_FILE}" ]; then
    export CHECK_DOMAIN="${DOMAIN}"
    envsubst '${CHECK_DOMAIN}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf
    echo "[entrypoint] Starting Nginx..."
    nginx
    echo "[entrypoint] Nginx started."
else
    echo "[entrypoint] WARNING: No cert found, skipping Nginx."
fi

# --- Start the Go service ---
echo "[entrypoint] Starting check.quip.network service..."
exec /usr/local/bin/check-quip
