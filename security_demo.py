# ===== CYBERSECURITY TOOLKIT - DEMO VERSION =====
# Simplified version that works better in terminals

from cryptography.fernet import Fernet
import hashlib
import base64
import os

print("\n" + "=" * 60)
print("🛡️  CYBERSECURITY TOOLKIT - QUICK DEMO")
print("=" * 60)
print()

# ===== DEMO 1: PASSWORD STRENGTH CHECKER =====
print("1️⃣  PASSWORD STRENGTH CHECKER")
print("-" * 60)

def check_password(pwd):
    import re
    score = 0
    feedback = []
    
    if len(pwd) >= 8: score += 1
    else: feedback.append("❌ Too short")
    
    if re.search(r'[A-Z]', pwd): score += 1
    else: feedback.append("❌ Add uppercase")
    
    if re.search(r'[a-z]', pwd): score += 1
    else: feedback.append("❌ Add lowercase")
    
    if re.search(r'\d', pwd): score += 1
    else: feedback.append("❌ Add numbers")
    
    if re.search(r'[!@#$%^&*]', pwd): score += 1
    else: feedback.append("❌ Add special chars")
    
    if score >= 5: strength = "🟢 STRONG"
    elif score >= 3: strength = "🟡 MEDIUM"
    else: strength = "🔴 WEAK"
    
    return strength, score, feedback

# Test passwords
test_passwords = ["password", "Password1", "P@ssw0rd!", "MySecureP@ss2025"]

for pwd in test_passwords:
    strength, score, feedback = check_password(pwd)
    print(f"\nPassword: '{pwd}'")
    print(f"Strength: {strength} ({score}/5)")
    if feedback:
        for f in feedback:
            print(f"  {f}")

# ===== DEMO 2: HASH CALCULATOR =====
print("\n\n2️⃣  HASH CALCULATOR (Password Hashing)")
print("-" * 60)

texts = ["MyPassword123", "SecretKey456", "admin"]

for text in texts:
    sha256_hash = hashlib.sha256(text.encode()).hexdigest()
    md5_hash = hashlib.md5(text.encode()).hexdigest()
    print(f"\nText: '{text}'")
    print(f"SHA-256: {sha256_hash}")
    print(f"MD5:     {md5_hash}")

# ===== DEMO 3: FILE ENCRYPTION =====
print("\n\n3️⃣  FILE ENCRYPTION DEMO")
print("-" * 60)

# Create a test file
test_file = "test_secret.txt"
with open(test_file, 'w') as f:
    f.write("This is top secret information!\nPassword: SuperSecret123\nAPI Key: sk-1234567890")

print(f"\n✅ Created test file: {test_file}")

# Generate encryption key
password = "MyEncryptionKey123"
key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
fernet = Fernet(key)

# Read and encrypt
with open(test_file, 'rb') as f:
    original_data = f.read()

encrypted_data = fernet.encrypt(original_data)

# Save encrypted file
encrypted_file = test_file + ".encrypted"
with open(encrypted_file, 'wb') as f:
    f.write(encrypted_data)

print(f"🔒 File encrypted: {encrypted_file}")
print(f"   Password used: {password}")

# Decrypt to verify
decrypted_data = fernet.decrypt(encrypted_data)
decrypted_file = test_file + ".decrypted"
with open(decrypted_file, 'wb') as f:
    f.write(decrypted_data)

print(f"🔓 File decrypted: {decrypted_file}")
print(f"   ✅ Decryption successful!")

# Show file contents
print(f"\n📄 Original file content:")
print("   " + open(test_file, 'r').read().replace('\n', '\n   '))

print(f"\n🔐 Encrypted file (binary):")
with open(encrypted_file, 'rb') as f:
    print(f"   {f.read()[:50]}... (truncated)")

print(f"\n✅ Decrypted file content:")
print("   " + open(decrypted_file, 'r').read().replace('\n', '\n   '))

# ===== DEMO 4: FILE HASH FOR INTEGRITY =====
print("\n\n4️⃣  FILE INTEGRITY VERIFICATION")
print("-" * 60)

def file_hash(filename):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        sha256.update(f.read())
    return sha256.hexdigest()

original_hash = file_hash(test_file)
decrypted_hash = file_hash(decrypted_file)

print(f"\nOriginal file hash:  {original_hash}")
print(f"Decrypted file hash: {decrypted_hash}")

if original_hash == decrypted_hash:
    print("✅ Files match! Encryption/Decryption was perfect!")
else:
    print("❌ Files don't match! Something went wrong!")

# ===== SUMMARY =====
print("\n\n" + "=" * 60)
print("🎉 CYBERSECURITY TOOLKIT DEMO COMPLETE!")
print("=" * 60)
print("""
✅ What you just saw:
   1. Password strength analysis (5 test passwords)
   2. Cryptographic hashing (SHA-256, MD5)
   3. File encryption with AES-256 (Fernet)
   4. File decryption
   5. File integrity verification

💼 This demonstrates:
   • Cryptography knowledge
   • Security best practices
   • Python proficiency
   • Real-world application

📁 Files created:
   • test_secret.txt          (original)
   • test_secret.txt.encrypted (encrypted)
   • test_secret.txt.decrypted (decrypted)

🎯 Perfect for your portfolio!
""")

print("\n💡 Want to try it yourself?")
print("   Type your own password to test:")
user_input = input("   Password: ")
if user_input:
    strength, score, feedback = check_password(user_input)
    print(f"\n   Your password: '{user_input}'")
    print(f"   Strength: {strength} ({score}/5)")
    if feedback:
        for f in feedback:
            print(f"   {f}")

print("\n" + "=" * 60)
print("🔐 Stay secure!")
print("=" * 60 + "\n")
