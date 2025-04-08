# PAdES Qualified Electronic Signature Emulator

## Overview
This application emulates the **PAdES (PDF Advanced Electronic Signature) Qualified Electronic Signature**, enabling users to sign PDF documents and verify their authenticity.

## Repository Structure
The project consists of two interconnected applications:

1. **RSAKeysGenerator**
2. **PAdES-app**

## RSAKeysGenerator
Generate secure RSA key pairs for digital signatures:

### Features
- Generates 4096-bit RSA key pairs
- Encrypts private keys using:
  - AES-256 encryption
  - Key derived from SHA-256 hash of user-provided PIN
- Outputs:
  - Public key: `.pem` format (unencrypted)
  - Private key: `.bin` format (encrypted)

### Usage
1. Enter a 6-digit PIN
2. Specify a base filename
3. Click "Generate RSA Keys"

## PAdES-app
Sign and verify PDF documents according to PAdES standards:

### Signing Features
- Select any PDF document
- Provide your encrypted private key (`*.bin`)
- Enter your 6-digit PIN to decrypt the key
- Generates a signed PDF by clicking "Sign PDF" button

### Verification Features
- Verify signed PDFs using:
  - The signed PDF document
  - Corresponding public key (`*.pem`)
  - "Verify PDF" button

## Technical Specifications
- **Algorithms**:
  - RSA-4096 for signatures
  - AES-256-CBC for private key encryption
  - SHA-256 for hashing
