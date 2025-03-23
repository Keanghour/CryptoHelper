# CryptoHelper
Tool Helper App is a versatile utility for encryption, key generation, and password management. It supports AES encryption/decryption, RSA key generation, AES key creation, and customizable password generation. Simplifying cryptography tasks, it offers an intuitive interface for secure data management.

---

# Tool Helper

Tool Helper is a Python application built with PyQt5 that provides several utilities for encryption, key generation, and password management. The app supports AES encryption/decryption, RSA key generation, AES key generation, and password generation with customizable options.

## Features

1. **Encryption/Decryption**
   - Encrypt and decrypt data using AES encryption with a provided secret key.

2. **AES Key Generation**
   - Generate AES keys of different sizes (128, 192, 256 bits) and an optional passphrase.

3. **RSA Key Generation**
   - Generate RSA public and private keys with selectable sizes (512 to 4096 bits) and output formats (PKCS-1, PKCS-8, OpenSSH, PuTTY).

4. **Password Generation**
   - Generate secure passwords with customizable options:
     - Length (8, 12, 16, 20, 24 characters)
     - Include numbers, lowercase, uppercase, and symbols
     - Option to avoid duplicates

## Requirements

- Python 3.x
- PyQt5
- pyperclip
- `aes_encryption` and `password_generator` modules (make sure to have these custom modules in your project)

## Installation

1. Clone the repository or download the source code.
2. Install dependencies:
   ```bash
   pip install pyqt5 pyperclip
   ```
3. Make sure to include the custom modules `aes_encryption.py` and `password_generator.py` in the same directory as the main app.

## Usage

1. Run the application:
   ```bash
   python tool_helper.py
   ```

2. Use the following tabs for each feature:
   - **Encryption/Decryption**: Enter the secret key and data, then encrypt or decrypt.
   - **Generate AES Key**: Select key size, optionally enter a passphrase, and generate an AES key.
   - **Generate RSA Keys**: Choose key size, format, and passphrase to generate RSA public/private keys.
   - **Generate Password**: Customize password options and generate a secure password.

3. Copy results to the clipboard using the "Copy" buttons and clear fields using the "Clear" buttons.

---

## Contact Me

Feel free to reach out if you have any questions or need further assistance:

- **Email**: [phokeanghour12@gmail.com](mailto:phokeanghour12@gmail.com)
- **Telegram**: [@phokeanghour](https://t.me/phokeanghour)

[![Telegram](https://www.vectorlogo.zone/logos/telegram/telegram-ar21.svg)](https://t.me/phokeanghour)
[![LinkedIn](https://www.vectorlogo.zone/logos/linkedin/linkedin-ar21.svg)](https://www.linkedin.com/in/pho-keanghour-27133b21b/)

---

**Credit**: This project was created by **Pho Keanghour**.

---

Let me know if this works or if you'd like any more adjustments!
