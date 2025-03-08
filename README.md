# AdvanceEncryptionTool
# Advanced Encryption Tool

## Overview
The **Advanced Encryption Tool** is a simple yet powerful application designed to encrypt and decrypt files using **AES-256 encryption**. It provides a **user-friendly interface** built with Tkinter, making it accessible for both beginners and professionals who need secure file encryption.

## Features
- **AES-256 Encryption**: Uses industry-standard AES encryption to secure files.
- **User-Friendly GUI**: No need to use command-line tools; a graphical interface makes encryption/decryption easy.
- **Randomized Salt & IV**: Each encryption is unique, even with the same password.
- **Password-Based Encryption**: Securely derives encryption keys using a password and PBKDF2 key derivation.

## Installation
### Prerequisites
Ensure you have **Python 3.x** installed along with the required dependencies.

### Install from GitHub
To clone and install the tool from GitHub, run the following commands:
```bash
git clone https://github.com/Hipster2110/AdvanceEncryptionTool.git
cd AdvanceEncryptionTool
pip install -r requirements.txt
```

### Install Dependencies Manually
If you prefer to install dependencies manually, run:
```bash
pip install cryptography
```

## Usage
### Running the Tool
To start the application, run:
```bash
python your_script.py
```
This will open the graphical user interface (GUI).

### Encrypting a File
1. Click **"Browse"** to select a file.
2. Enter the **output file name** (e.g., `my_secret.enc`).
3. Set a **strong password** (Remember it! You’ll need it for decryption).
4. Click **"Encrypt"** → The file will be securely encrypted and saved.

### Decrypting a File
1. Click **"Browse"** to select the encrypted file.
2. Enter the **output file name** (e.g., `decrypted.txt`).
3. Enter the **same password** used for encryption.
4. Click **"Decrypt"** → The original file will be restored.

## Security Considerations
- **Keep your password safe**: If you forget it, the file **cannot** be decrypted.
- **Do not modify encrypted files**: Any changes may corrupt the encryption, making decryption impossible.
- **Each encryption is unique**: Even with the same file and password, every encryption produces a different result due to randomized salt and IV.

## License
This project is open-source and available under the MIT License.

## Contributions
Feel free to fork, modify, and improve the tool! Pull requests are welcome.

## Author
[Hipster2110](https://github.com/Hipster2110)

---
Let me know if you need modifications! 🚀

