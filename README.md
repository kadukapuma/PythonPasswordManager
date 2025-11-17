# 🔐 PythonPasswordManager  
A modern, secure, and beautifully designed **Python-based desktop password manager** with AES-256 GCM encryption, PBKDF2 key derivation, strong password generator, search, CRUD UI, and master-password protection.

---

## 📌 Overview

**PythonPasswordManager** is a desktop application built using **Python + Tkinter** that allows users to **store, manage, and encrypt** their passwords safely.  
All stored passwords are **fully encrypted using AES-256-GCM**, and access is protected with a **master password** verified during application startup.  

🔹 No cloud storage  
🔹 No hidden services  
🔹 Fully offline and local  
🔹 Hacker-resistant encryption  

---


## ✨ Features

| Feature | Description |
|--------|-------------|
| AES-256-GCM Encryption | Industry-standard secure encryption |
| PBKDF2 Key Derivation | Prevents brute-force cracking |
| Master Password Protection | Required at launch |
| Password CRUD | Add, view, edit, delete |
| Strong Password Generator | Fully customizable |
| Search & Filtering | Fast and user-friendly |
| Copy to Clipboard | Secure instant copy |
| Notes field | Extra details per account |
| Offline Only | Runs without internet |
| `.exe` Build Support | Can run portable on Windows |

---

## 🏗 Tech Stack

| Component | Technology |
|----------|------------|
| Language  | Python 3 |
| UI        | Tkinter |
| Encryption| PyCryptodome |
| Clipboard | Pyperclip |
| Packaging | PyInstaller (optional) |

---

## 🔐 Security Architecture

| Layer | Method |
|--------|--------|
| Key Derivation | PBKDF2 (200,000 iterations) |
| Cipher | AES-256 GCM |
| Salt | Random 16-byte per encryption |
| Nonce | Random 12-byte |
| Data Storage | Fully encrypted JSON blob |
| Vault Integrity | GCM Authentication Tag |

---

## 📂 Vault Storage Location

Your encrypted vault is stored safely in the **AppData roaming directory**:

---
## 🚀 Installation & Usage

### **🔧 Option 1 — Run using Python**

#### **Requirements**

- Python 3.10+
- pip install pycryptodome pyperclip

---
## 🖥 Option 2 — Run the Windows .exe

### ** No installation required.**

- Download the .exe from the Exefile

- Run password_manager.exe

- Enter your master password

- Start storing passwords securely

⚠️ The .exe automatically creates and reads the encrypted vault file from the AppData path shown above.

---
## 🧱 Build Your Own .EXE (Optional)
- pip install pyinstaller
- pyinstaller --noconsole --onefile password_manager.py

---
## ⚠️ Important Notes

- Do not forget your master password — it cannot be recovered!

- Deleting vault.bin permanently erases all saved passwords

- Never share your master password or vault file

- Use a strong master password (min 10+ chars, mixed)


---
## 🤝 Contributing

### **Pull requests, suggestions, and improvements are welcome!**

---
## 📸 Screenshots

<img width="454" height="357" alt="PM1" src="https://github.com/user-attachments/assets/48ceef2c-0139-4646-9db0-4017f2910176" />
<img width="1205" height="737" alt="PM2" src="https://github.com/user-attachments/assets/62163d79-bf94-4858-b032-f45b2f558e65" />
