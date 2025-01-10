# SafeComms – Ephemeral Sign & Encrypt
**SafeComms** is a lightweight PHP application that demonstrates how to sign and encrypt text messages using **ephemeral keys**. These keys are generated fresh on each session and are never stored on disk or in any database, ensuring maximum confidentiality and privacy.
The web interface is divided into two columns:  
- **Left Column**: For signing and encrypting messages.  
- **Right Column**: For verifying and decrypting messages received from others.

---

## Overview

- **Ephemeral Keys on Every Session**  
  Every time the page is opened or refreshed, a new Ed25519 key pair is generated in memory.  
  - The keys change with each session/reload.  
  - Once the session ends or the page is closed, the keys vanish.  
  - No private keys are saved on the hard disk or in any form of database.  
  - As a result, previously encrypted messages become irrecoverable after the session ends.

- **Sign & Encrypt Messages**  
  - Uses **Ed25519** for digital signatures, ensuring authenticity and integrity of messages.
  - Uses **X25519** via libsodium functions for encryption, ensuring confidentiality.
  - The left column of the page allows the user to input a message, sign it with their private key, and encrypt it using the recipient's public key.

- **Verify & Decrypt Messages**  
  - The right column enables recipients to paste a signed and encrypted message along with the sender's public key.
  - The application will then decrypt the message and verify its signature, confirming its authenticity and integrity.

- **Privacy Features**  
  - The application does not log the real IP addresses of users.
  - Utilizes Apache's **mod_remoteip** to prevent storing client IP addresses in logs.

- **Secure Connection**  
  - The server is configured with **TLS 1.3** and **HTTP/2** for fast and secure communication.
  - Employs an Apache VirtualHost setup with these protocols on Debian GNU/Linux.

---

## Requirements

- **Debian** 11 (Bullseye) or later.
- **Apache** with:
  - PHP 8.3
  - TLS 1.3
  - HTTP/2
  - Modules: `mod_ssl`, `mod_http2`, `mod_remoteip`
- **libsodium** (bundled with PHP 8.3, supports Ed25519, X25519, etc.).
- **Composer** for dependency management.
- **OpenSSL ≥ 1.1.1** (for TLS 1.3 support).

---

## Installation Steps on Debian

1. **Install Apache, PHP 8.3, and required packages**  
   ```bash
   sudo apt-get update
   sudo apt-get install apache2 php8.3 php8.3-cli php8.3-common php8.3-sodium \
                        libapache2-mod-php8.3 openssl composer
