#!/bin/bash
# Convert one legacy Apple signing identity to a modern PKCS#12 bundle.

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 LEGACY_P12 MODERN_P12" >&2
    exit 2
fi

SOURCE_PATH="$1"
OUTPUT_PATH="$2"

if [ ! -f "$SOURCE_PATH" ]; then
    echo "Legacy PKCS#12 file does not exist: $SOURCE_PATH" >&2
    exit 1
fi
if [ -e "$OUTPUT_PATH" ]; then
    echo "Refusing to overwrite existing output: $OUTPUT_PATH" >&2
    exit 1
fi
command -v openssl >/dev/null 2>&1 || {
    echo "OpenSSL is required." >&2
    exit 1
}

umask 077
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/squirrelops-p12.XXXXXX")"
cleanup() {
    unset OLD_P12_PASSWORD NEW_P12_PASSWORD CONFIRM_P12_PASSWORD
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

read -r -s -p "Current PKCS#12 password: " OLD_P12_PASSWORD
printf '\n'
read -r -s -p "New PKCS#12 password: " NEW_P12_PASSWORD
printf '\n'
read -r -s -p "Confirm new PKCS#12 password: " CONFIRM_P12_PASSWORD
printf '\n'

if [ -z "$NEW_P12_PASSWORD" ]; then
    echo "The new PKCS#12 password must not be empty." >&2
    exit 1
fi
if [ "$NEW_P12_PASSWORD" != "$CONFIRM_P12_PASSWORD" ]; then
    echo "The new PKCS#12 passwords do not match." >&2
    exit 1
fi
export OLD_P12_PASSWORD NEW_P12_PASSWORD

if ! openssl pkcs12 \
    -legacy \
    -in "$SOURCE_PATH" \
    -info \
    -noout \
    -passin env:OLD_P12_PASSWORD >/dev/null 2>&1
then
    echo "The legacy PKCS#12 password or file is invalid." >&2
    exit 1
fi

CERTIFICATE_SUBJECT="$(
    openssl pkcs12 \
        -legacy \
        -in "$SOURCE_PATH" \
        -clcerts \
        -nokeys \
        -passin env:OLD_P12_PASSWORD 2>/dev/null \
        | openssl x509 -noout -subject
)"
case "$CERTIFICATE_SUBJECT" in
    *"Developer ID Application: Rocket Web Inc (PSQ5HK5U65)"*)
        IDENTITY_KIND="Developer ID Application"
        ;;
    *"Developer ID Installer: Rocket Web Inc (PSQ5HK5U65)"*)
        IDENTITY_KIND="Developer ID Installer"
        ;;
    *)
        echo "The source is not an expected Rocket Web Developer ID identity." >&2
        exit 1
        ;;
esac

openssl pkcs12 \
    -legacy \
    -in "$SOURCE_PATH" \
    -out "$TEMP_DIR/identity.pem" \
    -passin env:OLD_P12_PASSWORD \
    -passout env:NEW_P12_PASSWORD

openssl pkcs12 \
    -export \
    -in "$TEMP_DIR/identity.pem" \
    -out "$TEMP_DIR/modern.p12" \
    -name "$IDENTITY_KIND: Rocket Web Inc (PSQ5HK5U65)" \
    -passin env:NEW_P12_PASSWORD \
    -passout env:NEW_P12_PASSWORD \
    -keypbe AES-256-CBC \
    -certpbe AES-256-CBC \
    -macalg SHA256 \
    -iter 200000

MODERN_INFO="$(
    openssl pkcs12 \
        -in "$TEMP_DIR/modern.p12" \
        -info \
        -noout \
        -passin env:NEW_P12_PASSWORD 2>&1
)"
if printf '%s\n' "$MODERN_INFO" | grep -Fqi "RC2"; then
    echo "Modernized bundle unexpectedly retains RC2 encryption." >&2
    exit 1
fi
printf '%s\n' "$MODERN_INFO" | grep -Fqi "AES-256-CBC" || {
    echo "Modernized bundle does not report AES-256-CBC encryption." >&2
    exit 1
}
printf '%s\n' "$MODERN_INFO" | grep -Fqi "MAC: sha256" || {
    echo "Modernized bundle does not report a SHA-256 MAC." >&2
    exit 1
}
PRIVATE_KEY_COUNT="$(
    openssl pkcs12 \
        -in "$TEMP_DIR/modern.p12" \
        -nocerts \
        -nodes \
        -passin env:NEW_P12_PASSWORD 2>/dev/null \
        | grep -Ec 'BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY'
)"
if [ "$PRIVATE_KEY_COUNT" -ne 1 ]; then
    echo "Modernized bundle must contain exactly one private key." >&2
    exit 1
fi

install -m 600 "$TEMP_DIR/modern.p12" "$OUTPUT_PATH"
chmod 600 "$OUTPUT_PATH"
echo "Created $IDENTITY_KIND bundle: $OUTPUT_PATH"
