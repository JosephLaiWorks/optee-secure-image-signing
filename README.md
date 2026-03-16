# OP-TEE Secure Image Signing System

## Overview
This project implements a secure image signing system based on OP-TEE Trusted Execution Environment (TEE).

A client application running in the Rich Execution Environment (REE) reads an input image and sends it to a Trusted Application (TA). The TA computes the SHA-256 hash and generates an RSA-2048 digital signature inside the secure world.

The generated signature is returned to the REE and can be verified using OpenSSL with the exported public key.

## Features
- Image hashing using SHA-256 inside OP-TEE TA
- RSA-2048 digital signature generation in the TEE
- Persistent RSA key storage using secure storage
- Export of RSA public key components (modulus and exponent)
- Signature verification in REE using OpenSSL
- Support for verifying one image or multiple images

## System Architecture
Client Application (REE)
│
│ send image
▼
Trusted Application (TEE)
│
├─ SHA-256 hashing
├─ RSA-2048 signing
├─ secure storage for keys
└─ public key export

▼
Signature returned to REE

▼
OpenSSL verification (REE)

## Project Structure
optee-secure-image-signing/
├─ README.md
├─ LICENSE
├─ .gitignore
│
└─ save_pic
├─ host
│ ├─ main.c
│ ├─ verify_signature.c
│ ├─ verify_signature.h
│ └─ Makefile
│
└─ ta
├─ save_pic_ta.c
├─ user_ta_header_defines.h
├─ sub.mk
├─ Makefile
└─ include
└─ save_pic_ta.h

## Workflow

### 1. Signing (TEE)

1. The client application reads an image file.
2. The image is sent to the Trusted Application.
3. The TA computes the SHA-256 hash.
4. The TA signs the digest using an RSA-2048 private key.
5. The generated signature is returned to the client.

### 2. Verification (REE)

1. The verification program reads:
   - image file
   - signature file
   - RSA public key components (modulus and exponent)
2. SHA-256 is recomputed for the image.
3. OpenSSL verifies the signature using the public key.

## Notes

This repository contains only the core source code for the client application and Trusted Application.

Build artifacts, generated signatures, and temporary files are excluded using `.gitignore`.
