# CryptoAuditKeyManager
CryptoAuditKeyManager is a Qt-based desktop application designed for secure cryptographic key management, with a focus on forensic auditing and user authentication. The application allows users to generate, save, and verify RSA keys in PEM or SSH formats, manage user accounts, and maintain an audit trail for all actions. It integrates secure password hashing, account lockout mechanisms, and comprehensive error handling to ensure reliability and security.

# Table of Contents
- Features (#features)
- Dependencies (#dependencies)
- Installation (#installation)
- Usage (#usage)
- Project Structure (#project-structure)
- Security Features (#security-features)
- Contributing (#contributing)
- License (#license)

# Features
Key Generation and Management: Generate RSA keys (1024, 2048, or 4096 bits) in PEM or OpenSSH formats, with password protection and optional comments for SSH keys.
Key Verification: Verify private keys using a test message and SHA-256 signatures.
User Authentication: Secure user registration and login with Argon2id password hashing and account lockout after three failed attempts within five minutes.
Audit Trail: Log all actions (e.g., key generation, verification, login attempts) to a secure audit file with restricted permissions (0600).
Clipboard Support: Copy public keys to the clipboard for easy sharing.
Internationalization: Support for translations (currently locale-based, with English as default).
Error Handling: Comprehensive error reporting with severity levels (Info, Warning, Critical) and dialog-based user feedback.
First-Time Setup: Automatically prompts for admin user creation if no users exist in the database.


