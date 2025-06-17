# Cryptology: Symmetric AES Encryption (CBC) & Digital Signature

This repository contains two cryptographic implementations:  
1. **Symmetric AES Encryption** using CBC mode  
2. **Digital Signature** with RSA keys for PDF and Word files, implemented with a GUI interface.

---

## Table of Contents
1. [Project Descriptions](#project-descriptions)  
2. [Technologies Used](#technologies-used)
   
---

## Project Descriptions

### 1. Symmetric AES Encryption (CBC Mode)
A Python script that performs AES encryption and decryption using the **CBC (Cipher Block Chaining)** mode. It supports:
- Key generation of 16, 24, or 32 bytes.  
- Padding and unpadding of plaintext to match the AES block size (16 bytes).  
- Encrypted data and IV are encoded in **Base64** for readability.  

### 2. Digital Signature with GUI
A graphical application to sign and verify PDF and Word documents. Key features include:
- **RSA Key Generation**: Generates public and private RSA keys.
- **Signing Documents**: Adds a digital signature to PDF (as metadata) or Word files (as text).  
- **Verification**: Ensures the integrity of the document.  
- **GUI**: Built using `Tkinter` for an intuitive user interface.

---

## Technologies Used
- **Python**: Core programming language  
- **PyCryptodome**: Cryptography library for AES and RSA  
- **PyPDF2**: PDF processing library  
- **python-docx**: Word document handling  
- **Tkinter**: GUI toolkit for the digital signature app

## Author

**Ilija Popadic**  
[GitHub: ipopadic-ip](https://github.com/ipopadic-ip)

## License

This project is licensed under the **Attribution License**.

You are free to use, modify, and share this code for personal purposes, **as long as proper credit is given**.  
That includes:

- Mentioning my full name **Ilija Popadic** visibly in your project or documentation.
- Providing a working link to my GitHub profile: [https://github.com/ipopadic-ip](https://github.com/ipopadic-ip)

Failure to provide visible credit is a violation of this license.

---
