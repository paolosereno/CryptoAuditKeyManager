#include "keymanagerwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QCloseEvent>
#include <QPushButton>
#include <QComboBox>
#include <QFileDialog>
#include <QTextEdit>
#include <QDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QDebug>
#include <QRegularExpression>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <memory>
#include <QClipboard>
#include <QApplication>

KeyManagerWindow::KeyManagerWindow(const QString &auditFilePath, const QString &username, QWidget *parent)
    : QMainWindow(parent), m_username(username) {
    errorHandler = new ForensicErrorHandler(auditFilePath, username, this);
    setupUi();
    errorHandler->handleError(this, tr("Initialization"), tr("Key Manager started for user %1").arg(username), ForensicErrorHandler::Severity::Info, false);
}

KeyManagerWindow::~KeyManagerWindow() {
    delete errorHandler;
}

void KeyManagerWindow::setupUi() {
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // Password input
    QHBoxLayout *passwordLayout = new QHBoxLayout();
    QLabel *passwordLabel = new QLabel(tr("Key Password:"));
    passwordEdit = new QLineEdit();
    passwordEdit->setEchoMode(QLineEdit::Password);
    passwordLayout->addWidget(passwordLabel);
    passwordLayout->addWidget(passwordEdit);
    mainLayout->addLayout(passwordLayout);

    // Key length selection
    QHBoxLayout *keyLengthLayout = new QHBoxLayout();
    QLabel *keyLengthLabel = new QLabel(tr("Key Length:"));
    keyLengthCombo = new QComboBox();
    keyLengthCombo->addItems({"1024", "2048", "4096"});
    keyLengthCombo->setCurrentText("2048");
    keyLengthLayout->addWidget(keyLengthLabel);
    keyLengthLayout->addWidget(keyLengthCombo);
    mainLayout->addLayout(keyLengthLayout);

    // Key format selection
    QHBoxLayout *keyFormatLayout = new QHBoxLayout();
    QLabel *keyFormatLabel = new QLabel(tr("Key Format:"));
    keyFormatCombo = new QComboBox();
    keyFormatCombo->addItems({"PEM", "SSH"});
    keyFormatCombo->setCurrentText("PEM");
    keyFormatLayout->addWidget(keyFormatLabel);
    keyFormatLayout->addWidget(keyFormatCombo);
    mainLayout->addLayout(keyFormatLayout);

    // Comment input
    QHBoxLayout *commentLayout = new QHBoxLayout();
    QLabel *commentLabel = new QLabel(tr("SSH Key Comment:"));
    commentEdit = new QLineEdit();
    commentEdit->setPlaceholderText(tr("Enter comment or email for SSH public key (optional)"));
    commentLayout->addWidget(commentLabel);
    commentLayout->addWidget(commentEdit);
    mainLayout->addLayout(commentLayout);

    // Buttons
    generateButton = new QPushButton(tr("Generate and Save Key"));
    verifyButton = new QPushButton(tr("Verify Key"));
    showLogButton = new QPushButton(tr("Show Audit Log"));
    logoutButton = new QPushButton(tr("Logout"));
    copyPublicKeyButton = new QPushButton(tr("Copy Public Key to Clipboard")); // New button
    mainLayout->addWidget(generateButton);
    mainLayout->addWidget(verifyButton);
    mainLayout->addWidget(showLogButton);
    mainLayout->addWidget(logoutButton);
    mainLayout->addWidget(copyPublicKeyButton);
    mainLayout->addStretch();

    // Connections
    connect(generateButton, &QPushButton::clicked, this, &KeyManagerWindow::generateAndSaveKey);
    connect(verifyButton, &QPushButton::clicked, this, &KeyManagerWindow::verifyKey);
    connect(showLogButton, &QPushButton::clicked, this, &KeyManagerWindow::showAuditLog);
    connect(logoutButton, &QPushButton::clicked, this, &KeyManagerWindow::handleLogout);
    connect(copyPublicKeyButton, &QPushButton::clicked, this, &KeyManagerWindow::copyPublicKeyToClipboard); // New connection

    setWindowTitle(tr("Forensic Key Manager"));
    resize(400, 300); // Increased height to accommodate new button
}

void KeyManagerWindow::handleLogout() {
    errorHandler->logToAuditTrail("Logout", QString("User %1 logged out").arg(m_username));
    emit logoutRequested();
    close();
}

bool KeyManagerWindow::validatePassword(const QString &password) const {
    return password.length() >= 8 && password.contains(QRegularExpression("[A-Za-z0-9!@#$%^&*_]+"));
}

bool KeyManagerWindow::validateKeyLength(int keyLength) const {
    return keyLength == 1024 || keyLength == 2048 || keyLength == 4096;
}

void KeyManagerWindow::generateAndSaveKey() {
    QString password = passwordEdit->text();
    if (!validatePassword(password)) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Password must be at least 8 characters and include alphanumeric or special characters"), ForensicErrorHandler::Severity::Warning);
        return;
    }

    QString format = keyFormatCombo->currentText();
    QString fileFilter = format == "PEM" ? tr("PEM Files (*.pem)") : tr("SSH Key Files (*.key)");
    QString defaultExt = format == "PEM" ? ".pem" : ".key";
    QString keyPath = QFileDialog::getSaveFileName(this, tr("Save Private Key"), QDir::homePath(), fileFilter);
    if (keyPath.isEmpty()) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Key save canceled"), ForensicErrorHandler::Severity::Info);
        return;
    }
    if (!keyPath.endsWith(defaultExt)) {
        keyPath += defaultExt;
    }

    QString comment = commentEdit->text().trimmed();
    if (!validateComment(comment)) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Invalid comment: must be alphanumeric, spaces, hyphens, underscores, or a valid email address"), ForensicErrorHandler::Severity::Warning);
        return;
    }

    int keyLength = keyLengthCombo->currentText().toInt();
    if (!validateKeyLength(keyLength)) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Invalid key length"), ForensicErrorHandler::Severity::Warning);
        return;
    }

    // RAII for EVP_PKEY_CTX
    struct EVP_PKEY_CTXDeleter {
        void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
    };
    using EVP_PKEY_CTXPtr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTXDeleter>;

    // RAII for EVP_PKEY
    struct EVP_PKEYDeleter {
        void operator()(EVP_PKEY* pkey) const { EVP_PKEY_free(pkey); }
    };
    using EVP_PKEYPtr = std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter>;

    // Generate RSA key with EVP
    EVP_PKEY_CTXPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!ctx) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Failed to create EVP context: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Failed to initialize keygen: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), keyLength) <= 0) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Failed to set key length: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    EVP_PKEY *pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Failed to generate RSA key: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }
    EVP_PKEYPtr pkey(pkey_raw);

    // Open private key file
    QFile privateKeyFile(keyPath);
    if (!privateKeyFile.open(QIODevice::WriteOnly)) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Unable to open file: %1").arg(keyPath), ForensicErrorHandler::Severity::Critical);
        return;
    }

    FILE *privateKeyFp = fdopen(privateKeyFile.handle(), "w");
    if (!privateKeyFp) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Unable to open file descriptor: %1").arg(keyPath), ForensicErrorHandler::Severity::Critical);
        return;
    }

    // Save private key based on selected format
    QByteArray passwordBytes = password.toUtf8();
    if (format == "PEM") {
        // Save as PEM
        if (!PEM_write_PrivateKey(privateKeyFp, pkey.get(), EVP_aes_256_cbc(), (unsigned char*)passwordBytes.constData(),
                                  passwordBytes.length(), nullptr, nullptr)) {
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write PEM private key: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
            fclose(privateKeyFp);
            return;
        }
    } else if (format == "SSH") {
        // Save as SSH (OpenSSH format)
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio) {
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to create BIO for SSH key: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
            fclose(privateKeyFp);
            return;
        }

        // Convert RSA key to OpenSSH format
        if (!PEM_write_bio_PrivateKey_traditional(bio, pkey.get(), EVP_aes_256_cbc(), (unsigned char*)passwordBytes.constData(),
                                                  passwordBytes.length(), nullptr, nullptr)) {
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to convert to SSH private key: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
            BIO_free(bio);
            fclose(privateKeyFp);
            return;
        }

        // Write BIO content to file
        char *bio_data;
        long bio_len = BIO_get_mem_data(bio, &bio_data);
        if (fwrite(bio_data, 1, bio_len, privateKeyFp) != static_cast<size_t>(bio_len)) {
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write SSH private key to file"), ForensicErrorHandler::Severity::Critical);
            BIO_free(bio);
            fclose(privateKeyFp);
            return;
        }
        BIO_free(bio);
    }

    fclose(privateKeyFp);
    privateKeyFile.setPermissions(QFile::ReadOwner | QFile::WriteOwner); // Permissions 0600
    passwordBytes.fill(0); // Clear memory

    errorHandler->handleError(this, tr("Generate Key"), tr("Private key saved to %1 in %2 format").arg(keyPath, format), ForensicErrorHandler::Severity::Info);
    errorHandler->logToAuditTrail("Generate Key", tr("Generated and saved RSA-%1 key to %2 in %3 format").arg(keyLength).arg(keyPath, format));

    // Save public key
    QString publicKeyPath = keyPath + ".pub";
    QFile publicKeyFile(publicKeyPath);
    if (!publicKeyFile.open(QIODevice::WriteOnly)) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Unable to open public key file: %1").arg(publicKeyPath), ForensicErrorHandler::Severity::Warning);
        return;
    }

    FILE *publicKeyFp = fdopen(publicKeyFile.handle(), "w");
    if (!publicKeyFp) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Unable to open public key file descriptor: %1").arg(publicKeyPath), ForensicErrorHandler::Severity::Warning);
        return;
    }

    if (format == "PEM") {
        // Save public key as PEM
        if (!PEM_write_PUBKEY(publicKeyFp, pkey.get())) {
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write PEM public key: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Warning);
            fclose(publicKeyFp);
            return;
        }
    } else if (format == "SSH") {
        // Save public key in SSH format
        RSA *rsa = EVP_PKEY_get1_RSA(pkey.get());
        if (!rsa) {
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to extract RSA key: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Warning);
            fclose(publicKeyFp);
            return;
        }

        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio) {
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to create BIO for SSH public key: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Warning);
            RSA_free(rsa);
            fclose(publicKeyFp);
            return;
        }

        if (!PEM_write_bio_RSAPublicKey(bio, rsa)) {
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write RSA public key: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Warning);
            BIO_free(bio);
            RSA_free(rsa);
            fclose(publicKeyFp);
            return;
        }

        // Use user-provided comment or default to username@keymanager
        QString sshComment = comment.isEmpty() ? QString("%1@keymanager").arg(m_username) : comment;
        char *bio_data;
        long bio_len = BIO_get_mem_data(bio, &bio_data);
        QString sshPubKey = QString("ssh-rsa %1 %2\n").arg(QString(QByteArray(bio_data, bio_len).toBase64()), sshComment);
        if (fwrite(sshPubKey.toUtf8().constData(), 1, sshPubKey.toUtf8().length(), publicKeyFp) != static_cast<size_t>(sshPubKey.toUtf8().length())) {
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write SSH public key to file"), ForensicErrorHandler::Severity::Warning);
            BIO_free(bio);
            RSA_free(rsa);
            fclose(publicKeyFp);
            return;
        }
        BIO_free(bio);
        RSA_free(rsa);
    }

    fclose(publicKeyFp);
    publicKeyFile.setPermissions(QFile::ReadOwner | QFile::WriteOwner | QFile::ReadGroup | QFile::ReadOther); // Permissions 0644

    m_lastPublicKeyPath = publicKeyPath; // Store public key path
    errorHandler->handleError(this, tr("Generate Key"), tr("Public key saved to %1 in %2 format").arg(publicKeyPath, format), ForensicErrorHandler::Severity::Info);
    errorHandler->logToAuditTrail("Generate Key", tr("Saved public key to %1 in %2 format with comment '%3'").arg(publicKeyPath, format, comment.isEmpty() ? "default" : comment));
}

void KeyManagerWindow::verifyKey() {
    // Allow selection of both PEM and OpenSSH key files
    QString keyPath = QFileDialog::getOpenFileName(this, tr("Select Private Key"), QDir::homePath(), tr("Key Files (*.pem *.key)"));
    if (keyPath.isEmpty()) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Key selection canceled"), ForensicErrorHandler::Severity::Info);
        return;
    }

    QString password = QInputDialog::getText(this, tr("Key Password"), tr("Enter password for private key:"), QLineEdit::Password, QString());
    if (!validatePassword(password)) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Invalid password"), ForensicErrorHandler::Severity::Warning);
        return;
    }

    // RAII for EVP_PKEY
    struct EVP_PKEYDeleter {
        void operator()(EVP_PKEY* pkey) const { EVP_PKEY_free(pkey); }
    };
    using EVP_PKEYPtr = std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter>;

    // RAII for BIO
    struct BIODeleter {
        void operator()(BIO* bio) const { BIO_free(bio); }
    };
    using BIOPtr = std::unique_ptr<BIO, BIODeleter>;

    // RAII for EVP_MD_CTX
    struct EVP_MD_CTXDeleter {
        void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
    };
    using EVP_MD_CTXPtr = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTXDeleter>;

    // Read private key file
    QFile privateKeyFile(keyPath);
    if (!privateKeyFile.open(QIODevice::ReadOnly)) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Unable to open private key: %1").arg(keyPath), ForensicErrorHandler::Severity::Critical);
        return;
    }

    // Read file content into a BIO
    QByteArray keyData = privateKeyFile.readAll();
    BIOPtr bio(BIO_new_mem_buf(keyData.constData(), keyData.size()));
    if (!bio) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Failed to create BIO for key: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        privateKeyFile.close();
        return;
    }

    // Attempt to read private key (supports both PEM and OpenSSH formats)
    QByteArray passwordBytes = password.toUtf8();
    EVP_PKEY *pkey_raw = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, (void*)passwordBytes.constData());
    if (!pkey_raw) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Invalid private key or wrong password: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Warning);
        passwordBytes.fill(0); // Clear memory
        privateKeyFile.close();
        return;
    }
    EVP_PKEYPtr pkey(pkey_raw);
    passwordBytes.fill(0); // Clear memory
    privateKeyFile.close();

    // Verify with a test message
    const char *testMessage = "Test message for verification";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)testMessage, strlen(testMessage), hash);

    EVP_MD_CTXPtr md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Failed to create digest context: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    if (EVP_DigestSignInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Failed to initialize signing: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    if (EVP_DigestSignUpdate(md_ctx.get(), testMessage, strlen(testMessage)) <= 0) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Failed to update signing: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    size_t sigLen;
    if (EVP_DigestSignFinal(md_ctx.get(), nullptr, &sigLen) <= 0) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Failed to get signature length: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    std::unique_ptr<unsigned char[]> signature(new unsigned char[sigLen]);
    if (EVP_DigestSignFinal(md_ctx.get(), signature.get(), &sigLen) <= 0) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Failed to sign test message: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    // Verify the signature
    EVP_MD_CTXPtr verify_ctx(EVP_MD_CTX_new());
    if (!verify_ctx) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Failed to create digest context: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    if (EVP_DigestVerifyInit(verify_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Failed to initialize verification: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    if (EVP_DigestVerifyUpdate(verify_ctx.get(), testMessage, strlen(testMessage)) <= 0) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Failed to update verification: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    if (EVP_DigestVerifyFinal(verify_ctx.get(), signature.get(), sigLen) <= 0) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Key verification failed: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    // Determine key format for logging
    QString keyFormat = keyPath.endsWith(".pem") ? "PEM" : "OpenSSH";
    errorHandler->handleError(this, tr("Verify Key"), tr("Private key verified successfully (%1 format)").arg(keyFormat), ForensicErrorHandler::Severity::Info);
    errorHandler->logToAuditTrail("Verify Key", tr("Successfully verified %1 key %2").arg(keyFormat, keyPath));
}

void KeyManagerWindow::showAuditLog() {
    QDialog *logDialog = new QDialog(this);
    logDialog->setWindowTitle(tr("Audit Log"));
    logDialog->setMinimumSize(600, 400);

    QVBoxLayout *logLayout = new QVBoxLayout(logDialog);
    QTextEdit *logViewer = new QTextEdit(logDialog);
    logViewer->setReadOnly(true);
    logViewer->setFont(QFont("Courier New", 10));

    QPushButton *refreshButton = new QPushButton(tr("Refresh"), logDialog);
    QPushButton *clearButton = new QPushButton(tr("Clear Log"), logDialog);
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(refreshButton);
    buttonLayout->addWidget(clearButton);
    buttonLayout->addStretch();

    logLayout->addLayout(buttonLayout);
    logLayout->addWidget(logViewer);

    auto updateLogContent = [=]() {
        QFile logFile(errorHandler->getAuditFilePath());
        if (!logFile.exists()) {
            logViewer->setText(tr("No audit file found."));
            errorHandler->handleError(this, tr("Log Display"), tr("Audit file %1 does not exist.").arg(logFile.fileName()), ForensicErrorHandler::Severity::Info);
            return;
        }

        if (!logFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            logViewer->setText(tr("Error: Unable to read audit file."));
            errorHandler->handleError(this, tr("Log Display"), tr("Unable to open audit file %1: %2").arg(logFile.fileName(), logFile.errorString()), ForensicErrorHandler::Severity::Warning);
            return;
        }

        QTextStream in(&logFile);
        logViewer->setText(in.readAll());
        logFile.close();
        logViewer->moveCursor(QTextCursor::End);
    };

    connect(refreshButton, &QPushButton::clicked, updateLogContent);
    connect(clearButton, &QPushButton::clicked, [=]() {
        QFile logFile(errorHandler->getAuditFilePath());
        if (logFile.exists()) {
            if (logFile.remove()) {
                logViewer->setText(tr("Audit file cleared."));
                errorHandler->handleError(this, tr("Log Display"), tr("Audit file cleared successfully."), ForensicErrorHandler::Severity::Info);
                errorHandler->logToAuditTrail("Clear Log", tr("Audit file cleared"));
                // Crea un nuovo file con permessi restrittivi
                if (logFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
                    logFile.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
                    logFile.close();
                }
            } else {
                errorHandler->handleError(this, tr("Log Display"), tr("Unable to clear audit file: %1").arg(logFile.errorString()), ForensicErrorHandler::Severity::Warning);
            }
        } else {
            logViewer->setText(tr("No audit file to clear."));
        }
    });

    updateLogContent();
    logDialog->show();
}

void KeyManagerWindow::closeEvent(QCloseEvent *event) {
    errorHandler->logToAuditTrail("Window Closed", QString("User %1 closed the application").arg(m_username));
    emit logoutRequested(); // Emit signal to exit the main loop
    event->accept(); // Accept the close event
}

bool KeyManagerWindow::validateComment(const QString &comment) const {
    // Allow empty comments
    if (comment.isEmpty()) return true;

    // Regular expression for email address (simplified for SSH key comment)
    // Matches: alphanumeric, dots, hyphens, underscores, and @, e.g., user.name-123@example.com
    QRegularExpression emailRegex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");

    // Regular expression for general comment (alphanumeric, spaces, hyphens, underscores)
    QRegularExpression generalCommentRegex("^[A-Za-z0-9\\-_\\s]*$");

    // Check if the comment is either a valid email or matches the general comment pattern
    return emailRegex.match(comment).hasMatch() || generalCommentRegex.match(comment).hasMatch();
}

void KeyManagerWindow::copyPublicKeyToClipboard() {
    if (m_lastPublicKeyPath.isEmpty()) {
        errorHandler->handleError(this, tr("Copy Public Key"), tr("No public key has been generated yet"), ForensicErrorHandler::Severity::Warning);
        return;
    }

    QFile publicKeyFile(m_lastPublicKeyPath);
    if (!publicKeyFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        errorHandler->handleError(this, tr("Copy Public Key"), tr("Unable to open public key file: %1").arg(m_lastPublicKeyPath), ForensicErrorHandler::Severity::Warning);
        return;
    }

    QTextStream in(&publicKeyFile);
    QString publicKeyContent = in.readAll();
    publicKeyFile.close();

    if (publicKeyContent.isEmpty()) {
        errorHandler->handleError(this, tr("Copy Public Key"), tr("Public key file is empty: %1").arg(m_lastPublicKeyPath), ForensicErrorHandler::Severity::Warning);
        return;
    }

    // Copy to clipboard
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(publicKeyContent);

    // Determine key format for logging
    QString keyFormat = m_lastPublicKeyPath.endsWith(".pem.pub") ? "PEM" : "OpenSSH";
    errorHandler->handleError(this, tr("Copy Public Key"), tr("Public key copied to clipboard (%1 format)").arg(keyFormat), ForensicErrorHandler::Severity::Info);
    errorHandler->logToAuditTrail("Copy Public Key", tr("Copied public key from %1 (%2 format) to clipboard").arg(m_lastPublicKeyPath, keyFormat));
}
