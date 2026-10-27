#!/bin/sh

DOMAIN="${CHECK_DOMAIN:-check.quip.network}"
CERT_DIR="/etc/ssl"
CERT_FILE="${CERT_DIR}/${DOMAIN}.crt"
KEY_FILE="${CERT_DIR}/${DOMAIN}.key"

# --- Replace the system trust store with the image's on every boot ---
# /etc/ssl is the app's persistent volume, and it shadows the image's own
# /etc/ssl. Go verifies /probe's tls, rpc, telemetry and dashboard checks
# against the bundle in it. A missing bundle turns all four into "x509:
# certificate signed by unknown authority" while the raw-TCP checks keep
# passing. A stale one is worse: a bundle restored once and kept forever never
# loses a root, so it kept trusting the forged eMudhra chain (QUI-1923) through
# every rebuild. The trust store is not user data, so overwrite it. The issued
# cert and key sit beside it and are never touched. If the copy fails, stop
# rather than serve TLS verdicts from a store we could not refresh.
mkdir -p "${CERT_DIR}/certs"
for f in certs/ca-certificates.crt cert.pem; do
    src="/opt/ssl-defaults/${f}"
    dst="${CERT_DIR}/${f}"
    cmp -s "${src}" "${dst}" && continue
    if [ -e "${dst}" ]; then
        echo "[entrypoint] ${dst} differs from the image's trust store, replacing it."
    else
        echo "[entrypoint] ${dst} missing, restoring it from the image."
    fi
    if ! { cp "${src}" "${dst}.tmp" && mv "${dst}.tmp" "${dst}" && cmp -s "${src}" "${dst}"; }; then
        echo "[entrypoint] FATAL: could not refresh ${dst} from the image."
        exit 1
    fi
done

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
