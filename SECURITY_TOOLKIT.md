# 🛡️ Cybersecurity Toolkit - Professional Security Tool

## 📋 Overview
A comprehensive, professional-grade cybersecurity toolkit built with Python that demonstrates real-world security capabilities. This tool is perfect for portfolio showcases and practical security tasks.

## ✨ Features

### 🔒 File Encryption/Decryption
- **AES-256 Encryption** using Fernet (symmetric encryption)
- Password-based key derivation
- Encrypt any file type (documents, images, etc.)
- Decrypt files with correct password
- Automatic file naming (.encrypted extension)

### #️⃣ Hash Calculator
- **Multiple Algorithms**: MD5, SHA1, SHA256, SHA512
- Hash text/passwords
- Hash entire files
- Verify file integrity
- Compare hashes

### 🔑 Password Strength Analyzer
- Comprehensive password analysis
- 7-point scoring system
- Detailed recommendations
- Detects common patterns
- Security best practices

### 📊 Statistics Dashboard
- Track all encryption/decryption operations
- Hash calculation history
- Activity timestamps
- Usage analytics

## 🚀 How to Use

### Installation

1. **Install dependencies:**
```bash
cd my-portfolio
pip install cryptography
```

2. **Run the toolkit:**
```bash
python security_toolkit.py
```

### Quick Start Guide

#### 1️⃣ Encrypt a File
```
Choose option 1 → Encrypt a file
Enter file path: secret_file.txt
Enter password: [your secure password]
Result: secret_file.txt.encrypted
```

#### 2️⃣ Decrypt a File
```
Choose option 1 → Decrypt a file
Enter file path: secret_file.txt.encrypted
Enter password: [same password used for encryption]
Result: secret_file.txt.decrypted
```

#### 3️⃣ Calculate Hash
```
Choose option 2 → Hash text/password
Enter text: MyPassword123
Choose algorithm: sha256
Result: Hash value displayed
```

#### 4️⃣ Check Password Strength
```
Choose option 3
Enter password: [password to test]
Result: Strength score + recommendations
```

## 🔧 Technical Details

### Encryption Method
- **Algorithm**: AES-256 (Fernet)
- **Key Derivation**: SHA-256 password hashing
- **Mode**: CBC with authentication
- **Library**: Python Cryptography (industry-standard)

### Hash Algorithms Supported
- **MD5**: Legacy, fast (128-bit)
- **SHA1**: Legacy (160-bit)
- **SHA256**: Recommended (256-bit)
- **SHA512**: Maximum security (512-bit)

### Security Features
- ✅ No password storage (password-based encryption)
- ✅ Secure password input (hidden typing)
- ✅ Activity logging
- ✅ Error handling
- ✅ File integrity verification

## 📁 File Structure

```
my-portfolio/
├── security_toolkit.py      # Main program
├── secret_file.txt          # Demo file to encrypt
├── security_config.json     # Auto-generated config
└── SECURITY_TOOLKIT.md      # This file
```

## 💼 Portfolio Value

**This project demonstrates:**

✅ **Cryptography Knowledge**
- Understanding of encryption algorithms
- Proper key management
- Security best practices

✅ **Python Proficiency**
- Object-oriented programming
- File I/O operations
- Exception handling
- External library usage

✅ **Security Awareness**
- Password security
- Data protection
- Threat mitigation

✅ **Professional Code**
- Clean architecture
- User-friendly interface
- Documentation
- Error handling

## 🎯 Use Cases

### Personal Use
- Encrypt sensitive documents
- Secure password storage
- File integrity verification
- Security awareness training

### Professional Applications
- Data protection demonstrations
- Security training tools
- File encryption services
- Password policy enforcement

### Educational
- Learn cryptography concepts
- Understand hashing
- Practice secure coding
- Security best practices

## 📊 Example Usage

### Encrypt Your Resume
```bash
python security_toolkit.py
→ 1 (File Encryption)
→ 1 (Encrypt)
→ File: resume.pdf
→ Password: MySecurePass123!
✅ resume.pdf.encrypted created
```

### Verify File Integrity
```bash
python security_toolkit.py
→ 2 (Hash Calculator)
→ 2 (Hash file)
→ File: important_document.pdf
→ Algorithm: sha256
✅ Hash: 3a7b...c2f1
```

### Test Password Security
```bash
python security_toolkit.py
→ 3 (Password Checker)
→ Password: MyPassword123
📊 Strength: MEDIUM (4/7)
⚠️  Add special characters
```

## ⚠️ Important Notes

### Security Warnings
- **Keep passwords secure** - Cannot decrypt without password
- **Backup important files** - Before encryption
- **Use strong passwords** - For encryption
- **Store hashes safely** - For verification

### Best Practices
1. Use SHA-256 or SHA-512 for hashing
2. Create strong passwords (12+ characters)
3. Keep encrypted files secure
4. Test encryption with non-critical files first
5. Never share encryption passwords

## 🚀 Future Enhancements

Potential additions:
- [ ] Public/Private key encryption (RSA)
- [ ] File compression before encryption
- [ ] Batch file encryption
- [ ] Password manager with encryption
- [ ] Network security scanner
- [ ] GUI interface (tkinter)
- [ ] Cloud storage integration

## 📚 Learning Resources

**To understand this code better, study:**
- Symmetric vs Asymmetric Encryption
- Fernet (Python cryptography)
- Hash functions and their uses
- Password security best practices
- File I/O in Python

## 💡 Add to Resume

```
Cybersecurity Toolkit | Python, Cryptography
• Built professional security tool with AES-256 encryption
• Implemented multi-algorithm hash calculator (MD5, SHA1, SHA256, SHA512)
• Created password strength analyzer with 7-point scoring system
• Developed secure file encryption/decryption system
• Technologies: Python, Cryptography library, JSON
```

## 🔗 Related Projects

Pair this with:
- Portfolio Backend API
- Network Security Scanner
- Password Manager
- Penetration Testing Tools

---

**Built with 🔐 by Chima Njoku**
*Demonstrating real-world cybersecurity skills*
