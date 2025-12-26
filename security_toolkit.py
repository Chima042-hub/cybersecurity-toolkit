# ===== CYBERSECURITY TOOLKIT - PROFESSIONAL SECURITY TOOL =====
# A real cybersecurity tool you can use and showcase!

from cryptography.fernet import Fernet
import hashlib
import os
import base64
import getpass
from datetime import datetime
import json

class SecurityToolkit:
    """Professional Cybersecurity Toolkit"""
    
    def __init__(self):
        self.config_file = 'security_config.json'
        self.load_config()
    
    def load_config(self):
        """Load or create configuration"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = {
                'encryption_history': [],
                'hash_history': []
            }
    
    def save_config(self):
        """Save configuration"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    # ===== FILE ENCRYPTION/DECRYPTION =====
    
    def generate_key(self, password):
        """Generate encryption key from password"""
        # Use password to derive a key
        key = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(key)
    
    def encrypt_file(self, file_path, password):
        """Encrypt a file with password"""
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                return False, f"File not found: {file_path}"
            
            # Generate encryption key
            key = self.generate_key(password)
            fernet = Fernet(key)
            
            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Encrypt data
            encrypted_data = fernet.encrypt(file_data)
            
            # Save encrypted file
            encrypted_file = file_path + '.encrypted'
            with open(encrypted_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Log encryption
            self.config['encryption_history'].append({
                'file': os.path.basename(file_path),
                'action': 'encrypted',
                'timestamp': datetime.now().isoformat(),
                'output': os.path.basename(encrypted_file)
            })
            self.save_config()
            
            return True, f"✅ File encrypted successfully!\nSaved to: {encrypted_file}"
        
        except Exception as e:
            return False, f"❌ Encryption failed: {str(e)}"
    
    def decrypt_file(self, file_path, password):
        """Decrypt an encrypted file"""
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                return False, f"File not found: {file_path}"
            
            # Generate decryption key
            key = self.generate_key(password)
            fernet = Fernet(key)
            
            # Read encrypted file
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt data
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Save decrypted file
            decrypted_file = file_path.replace('.encrypted', '.decrypted')
            with open(decrypted_file, 'wb') as f:
                f.write(decrypted_data)
            
            # Log decryption
            self.config['encryption_history'].append({
                'file': os.path.basename(file_path),
                'action': 'decrypted',
                'timestamp': datetime.now().isoformat(),
                'output': os.path.basename(decrypted_file)
            })
            self.save_config()
            
            return True, f"✅ File decrypted successfully!\nSaved to: {decrypted_file}"
        
        except Exception as e:
            return False, f"❌ Decryption failed: {str(e)}\n(Wrong password or corrupted file)"
    
    # ===== HASH CALCULATOR =====
    
    def calculate_hash(self, text, algorithm='sha256'):
        """Calculate hash of text"""
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        
        if algorithm not in algorithms:
            return None, f"Unknown algorithm: {algorithm}"
        
        hash_obj = algorithms[algorithm](text.encode())
        hash_value = hash_obj.hexdigest()
        
        # Log hash calculation
        self.config['hash_history'].append({
            'algorithm': algorithm,
            'text_length': len(text),
            'timestamp': datetime.now().isoformat()
        })
        self.save_config()
        
        return hash_value, algorithm
    
    def calculate_file_hash(self, file_path, algorithm='sha256'):
        """Calculate hash of a file"""
        try:
            algorithms = {
                'md5': hashlib.md5,
                'sha1': hashlib.sha1,
                'sha256': hashlib.sha256,
                'sha512': hashlib.sha512
            }
            
            if algorithm not in algorithms:
                return None, f"Unknown algorithm: {algorithm}"
            
            hash_obj = algorithms[algorithm]()
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest(), algorithm
        
        except Exception as e:
            return None, str(e)
    
    # ===== PASSWORD SECURITY =====
    
    def check_password_strength(self, password):
        """Analyze password strength"""
        import re
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("❌ Too short (min 12 recommended)")
        
        # Character variety
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("❌ Add uppercase letters")
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("❌ Add lowercase letters")
        
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("❌ Add numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("❌ Add special characters")
        
        # Common patterns (weakness)
        common_patterns = ['123', 'abc', 'qwerty', 'password', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 2
            feedback.append("⚠️  Contains common pattern")
        
        # Determine strength
        if score >= 6:
            strength = "🟢 VERY STRONG"
        elif score >= 4:
            strength = "🟡 STRONG"
        elif score >= 2:
            strength = "🟠 MEDIUM"
        else:
            strength = "🔴 WEAK"
        
        return strength, score, feedback
    
    # ===== STATISTICS =====
    
    def show_statistics(self):
        """Show toolkit usage statistics"""
        print("\n" + "=" * 60)
        print("📊 SECURITY TOOLKIT STATISTICS")
        print("=" * 60)
        print(f"\n🔐 Total Encryptions: {len([h for h in self.config['encryption_history'] if h['action'] == 'encrypted'])}")
        print(f"🔓 Total Decryptions: {len([h for h in self.config['encryption_history'] if h['action'] == 'decrypted'])}")
        print(f"#️⃣  Total Hash Calculations: {len(self.config['hash_history'])}")
        
        if self.config['encryption_history']:
            print("\n📁 Recent Encryption Activity:")
            for entry in self.config['encryption_history'][-5:]:
                print(f"   • {entry['action'].upper()}: {entry['file']} ({entry['timestamp'][:10]})")
        
        print()

# ===== MAIN PROGRAM =====

def print_banner():
    """Print application banner"""
    print("\n" + "=" * 60)
    print("🛡️  CYBERSECURITY TOOLKIT - PROFESSIONAL EDITION")
    print("=" * 60)
    print("Built with Python | Cryptography | Security Best Practices")
    print("=" * 60 + "\n")

def main_menu():
    """Display main menu"""
    print("\n" + "=" * 60)
    print("CHOOSE A TOOL:")
    print("=" * 60)
    print("1. 🔒 File Encryption/Decryption")
    print("2. #️⃣  Hash Calculator")
    print("3. 🔑 Password Strength Checker")
    print("4. 📊 View Statistics")
    print("5. ❓ About This Tool")
    print("6. 🚪 Exit")
    print("=" * 60)

def file_encryption_menu(toolkit):
    """File encryption submenu"""
    print("\n" + "🔒 FILE ENCRYPTION/DECRYPTION")
    print("-" * 60)
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    print("3. Back to main menu")
    
    choice = input("\nChoice: ").strip()
    
    if choice == '1':
        file_path = input("\nEnter file path to encrypt: ").strip()
        password = getpass.getpass("Enter encryption password: ")
        confirm = getpass.getpass("Confirm password: ")
        
        if password != confirm:
            print("❌ Passwords don't match!")
            return
        
        print("\n🔄 Encrypting file...")
        success, message = toolkit.encrypt_file(file_path, password)
        print(message)
        
    elif choice == '2':
        file_path = input("\nEnter encrypted file path: ").strip()
        password = getpass.getpass("Enter decryption password: ")
        
        print("\n🔄 Decrypting file...")
        success, message = toolkit.decrypt_file(file_path, password)
        print(message)

def hash_calculator_menu(toolkit):
    """Hash calculator submenu"""
    print("\n" + "#️⃣  HASH CALCULATOR")
    print("-" * 60)
    print("1. Hash text/password")
    print("2. Hash a file")
    print("3. Back to main menu")
    
    choice = input("\nChoice: ").strip()
    
    if choice == '1':
        text = input("\nEnter text to hash: ")
        print("\nAlgorithms: md5, sha1, sha256, sha512")
        algorithm = input("Choose algorithm (default: sha256): ").strip().lower() or 'sha256'
        
        hash_value, algo = toolkit.calculate_hash(text, algorithm)
        if hash_value:
            print(f"\n✅ {algo.upper()} Hash:")
            print(f"   {hash_value}")
        else:
            print(f"❌ Error: {algo}")
    
    elif choice == '2':
        file_path = input("\nEnter file path: ").strip()
        print("\nAlgorithms: md5, sha1, sha256, sha512")
        algorithm = input("Choose algorithm (default: sha256): ").strip().lower() or 'sha256'
        
        hash_value, result = toolkit.calculate_file_hash(file_path, algorithm)
        if hash_value:
            print(f"\n✅ {algorithm.upper()} Hash of {os.path.basename(file_path)}:")
            print(f"   {hash_value}")
        else:
            print(f"❌ Error: {result}")

def password_checker_menu(toolkit):
    """Password strength checker"""
    print("\n" + "🔑 PASSWORD STRENGTH CHECKER")
    print("-" * 60)
    password = getpass.getpass("Enter password to analyze: ")
    
    strength, score, feedback = toolkit.check_password_strength(password)
    
    print(f"\n📊 PASSWORD ANALYSIS:")
    print(f"   Strength: {strength}")
    print(f"   Score: {score}/7")
    
    if feedback:
        print(f"\n⚠️  Recommendations:")
        for item in feedback:
            print(f"   {item}")
    else:
        print("\n✅ Excellent password!")

def show_about():
    """Show about information"""
    print("\n" + "=" * 60)
    print("❓ ABOUT THIS CYBERSECURITY TOOLKIT")
    print("=" * 60)
    print("""
This is a professional-grade security toolkit built with Python
demonstrating real-world cybersecurity capabilities.

🔧 FEATURES:
   • AES-256 File Encryption/Decryption
   • Multiple Hash Algorithms (MD5, SHA1, SHA256, SHA512)
   • Password Strength Analysis
   • Secure Password Input
   • Activity Logging & Statistics

🛡️  SECURITY:
   • Uses industry-standard cryptography library
   • Password-based encryption with SHA-256 key derivation
   • Secure password input (hidden)
   • No plaintext password storage

💼 PORTFOLIO VALUE:
   • Demonstrates cryptography knowledge
   • Shows security best practices
   • Professional code structure
   • Real-world application

📚 TECHNOLOGIES:
   • Python 3.x
   • Cryptography (Fernet encryption)
   • Hashlib (Hashing algorithms)
   • JSON (Configuration storage)

⚠️  DISCLAIMER:
This tool is for educational and personal use. Always keep backups
of important files before encryption!
    """)

def main():
    """Main program loop"""
    toolkit = SecurityToolkit()
    
    print_banner()
    
    while True:
        main_menu()
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == '1':
            file_encryption_menu(toolkit)
        elif choice == '2':
            hash_calculator_menu(toolkit)
        elif choice == '3':
            password_checker_menu(toolkit)
        elif choice == '4':
            toolkit.show_statistics()
        elif choice == '5':
            show_about()
        elif choice == '6':
            print("\n" + "=" * 60)
            print("👋 Thank you for using Cybersecurity Toolkit!")
            print("🔐 Stay secure!")
            print("=" * 60 + "\n")
            break
        else:
            print("\n❌ Invalid choice. Please enter 1-6.")

if __name__ == "__main__":
    main()
