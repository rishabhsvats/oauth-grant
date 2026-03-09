#!/bin/bash

# Script to export private key from JKS keystore
# Usage: ./export-key.sh <keystore.jks> <alias> <keystore-password> [output-key.pem]

if [ $# -lt 3 ]; then
    echo "Usage: $0 <keystore.jks> <alias> <keystore-password> [output-key.pem]"
    echo ""
    echo "Example:"
    echo "  $0 keystore.jks mykey mypassword private-key.pem"
    exit 1
fi

JKS_FILE="$1"
ALIAS="$2"
PASSWORD="$3"
OUTPUT_FILE="${4:-private-key.pem}"
TEMP_P12="temp_keystore.p12"

echo "Step 1: Converting JKS to PKCS12 format..."
keytool -importkeystore \
    -srckeystore "$JKS_FILE" \
    -srcstorepass "$PASSWORD" \
    -srcalias "$ALIAS" \
    -destkeystore "$TEMP_P12" \
    -deststoretype PKCS12 \
    -deststorepass "$PASSWORD" \
    -destkeypass "$PASSWORD" \
    -noprompt

if [ $? -ne 0 ]; then
    echo "Error: Failed to convert JKS to PKCS12"
    exit 1
fi

echo "Step 2: Extracting private key from PKCS12..."
openssl pkcs12 -in "$TEMP_P12" \
    -nodes \
    -nocerts \
    -out "$OUTPUT_FILE" \
    -passin pass:"$PASSWORD"

if [ $? -ne 0 ]; then
    echo "Error: Failed to extract private key"
    rm -f "$TEMP_P12"
    exit 1
fi

# Clean up temporary file
rm -f "$TEMP_P12"

echo ""
echo "Success! Private key exported to: $OUTPUT_FILE"
echo ""
echo "To use with the OAuth application, set:"
echo "  export OAUTH_PRIVATE_KEY_PATH=$OUTPUT_FILE"
echo ""
echo "Note: Make sure to secure this file with appropriate permissions:"
echo "  chmod 600 $OUTPUT_FILE"

