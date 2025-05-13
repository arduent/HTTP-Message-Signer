#!/usr/bin/bash

# A. Ed25519 Key Pair (OpenSSL)
# Generate Ed25519 Private Key and extract Public Key

openssl genpkey -algorithm ED25519 -out ed25519-private.pem
openssl pkey -in ed25519-private.pem -pubout -out ed25519-public.pem

# B. HMAC Key (Random Secret Key)
head -c 32 /dev/urandom | base64 > hmac.key

# C. RSA  
# Generate RSA Private Key and Public Key

openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem

