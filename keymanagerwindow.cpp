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
#include <openssl/opensslv.h>
#include <memory>
#include <QClipboard>
#include <QApplication>
#include <QTranslator>

// Helper function to securely clear sensitive data
static void secureClear(QByteArray &data) {
    std::fill(data.begin(), data.end(), 0);
}

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

    // Key type selection
    QHBoxLayout *keyTypeLayout = new QHBoxLayout();
    QLabel *keyTypeLabel = new QLabel(tr("Key Type:"));
    keyTypeCombo = new QComboBox();
    keyTypeCombo->addItems({"RSA", "ECDSA", "Ed25519"});
    keyTypeCombo->setCurrentText("RSA");
    keyTypeLayout->addWidget(keyTypeLabel);
    keyTypeLayout->addWidget(keyTypeCombo);
    mainLayout->addLayout(keyTypeLayout);

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
    keyFormatCombo->addItems({"PEM", "SSH", "DER", "PKCS#8"});
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

    // Language selection
    QHBoxLayout *languageLayout = new QHBoxLayout();
    QLabel *languageLabel = new QLabel(tr("Language:"));
    languageCombo = new QComboBox();
    languageCombo->addItems({"en_US", "it_IT", "es_ES"});
    languageCombo->setCurrentText(QLocale::system().name());
    languageLayout->addWidget(languageLabel);
    languageLayout->addWidget(languageCombo);
    mainLayout->addLayout(languageLayout);

    // Buttons
    generateButton = new QPushButton(tr("Generate and Save Key"));
    verifyButton = new QPushButton(tr("Verify Key"));
    showLogButton = new QPushButton(tr("Show Audit Log"));
    logoutButton = new QPushButton(tr("Logout"));
    copyPublicKeyButton = new QPushButton(tr("Copy Public Key to Clipboard"));
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
    connect(copyPublicKeyButton, &QPushButton::clicked, this, &KeyManagerWindow::copyPublicKeyToClipboard);
    connect(languageCombo, &QComboBox::currentTextChanged, this, &KeyManagerWindow::changeLanguage);
    connect(keyTypeCombo, &QComboBox::currentTextChanged, this, [=](const QString &keyType) {
        keyLengthCombo->clear();
        keyFormatCombo->clear();
        if (keyType == "RSA") {
            keyLengthCombo->addItems({"1024", "2048", "4096"});
            keyLengthCombo->setCurrentText("2048");
            keyFormatCombo->addItems({"PEM", "SSH", "DER", "PKCS#8"});
        } else if (keyType == "ECDSA") {
            keyLengthCombo->addItems({"256", "384", "521"});
            keyLengthCombo->setCurrentText("256");
            keyFormatCombo->addItems({"PEM", "SSH", "DER", "PKCS#8"});
        } else if (keyType == "Ed25519") {
            keyLengthCombo->addItems({"256"});
            keyLengthCombo->setCurrentText("256");
            keyFormatCombo->addItems({"PEM", "SSH"}); // DER e PKCS#8 non supportati per Ed25519
        }
        keyFormatCombo->setCurrentText("PEM");
    });

    setWindowTitle(tr("Forensic Key Manager"));
    resize(400, 360);
}

void KeyManagerWindow::handleLogout() {
    errorHandler->logToAuditTrail(tr("Logout"), tr("User %1 logged out").arg(m_username));
    emit logoutRequested();
    close();
}

bool KeyManagerWindow::validatePassword(const QString &password) const {
    QRegularExpression regex("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[!@#$%^&*])[A-Za-z\\d!@#$%^&*]{12,}$");
    bool isValid = regex.match(password).hasMatch();
    if (!isValid) {
        errorHandler->handleError(this, tr("Password Validation"),
                                  tr("Password must be at least 12 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character (!@#$%^&*)."),
                                  ForensicErrorHandler::Severity::Warning);
    }
    return isValid;
}

bool KeyManagerWindow::validateKeyLength(int keyLength, const QString &keyType) const {
    if (keyType == "RSA") {
        return keyLength == 1024 || keyLength == 2048 || keyLength == 4096;
    } else if (keyType == "ECDSA") {
        return keyLength == 256 || keyLength == 384 || keyLength == 521;
    } else if (keyType == "Ed25519") {
        return keyLength == 256;
    }
    return false;
}

bool KeyManagerWindow::validateComment(const QString &comment) const {
    if (comment.isEmpty()) return true;

    QRegularExpression emailRegex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    QRegularExpression generalCommentRegex("^[A-Za-z0-9\\-_\\s]*$");
    return emailRegex.match(comment).hasMatch() || generalCommentRegex.match(comment).hasMatch();
}

bool KeyManagerWindow::validateKeyType(const QString &keyType) const {
    return keyType == "RSA" || keyType == "ECDSA" || keyType == "Ed25519";
}

bool KeyManagerWindow::isKeyTypeSupportedForFormat(const QString &keyType, const QString &format) const {
    if (format == "PEM" || format == "SSH") {
        return true; // PEM e SSH supportano tutti i tipi di chiave
    } else if (format == "DER" || format == "PKCS#8") {
        return keyType == "RSA" || keyType == "ECDSA"; // DER e PKCS#8 supportano solo RSA e ECDSA
    }
    return false;
}

void KeyManagerWindow::generateAndSaveKey() {
    // Validazione della password
    QString password = passwordEdit->text();
    if (!validatePassword(password)) {
        errorHandler->handleError(this, tr("Generate Key"),
                                  tr("Password must be at least 12 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character (!@#$%^&*)."),
                                  ForensicErrorHandler::Severity::Warning);
        return;
    }

    // Validazione del tipo di chiave
    QString keyType = keyTypeCombo->currentText();
    if (!validateKeyType(keyType)) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Invalid key type"), ForensicErrorHandler::Severity::Warning);
        return;
    }

    // Validazione della lunghezza della chiave
    int keyLength = keyLengthCombo->currentText().toInt();
    if (!validateKeyLength(keyLength, keyType)) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Invalid key length for %1").arg(keyType),
                                  ForensicErrorHandler::Severity::Warning);
        return;
    }

    // Selezione del formato e validazione
    QString format = keyFormatCombo->currentText();
    if (!isKeyTypeSupportedForFormat(keyType, format)) {
        errorHandler->handleError(this, tr("Generate Key"),
                                  tr("Format %1 is not supported for key type %2").arg(format, keyType),
                                  ForensicErrorHandler::Severity::Warning);
        return;
    }

    QString fileFilter, defaultExt;
    if (format == "PEM") {
        fileFilter = tr("PEM Files (*.pem)");
        defaultExt = ".pem";
    } else if (format == "SSH") {
        fileFilter = tr("SSH Key Files (*.key)");
        defaultExt = ".key";
    } else if (format == "DER") {
        fileFilter = tr("DER Files (*.der)");
        defaultExt = ".der";
    } else if (format == "PKCS#8") {
        fileFilter = tr("PKCS#8 Files (*.p8)");
        defaultExt = ".p8";
    } else {
        errorHandler->handleError(this, tr("Generate Key"), tr("Invalid key format"), ForensicErrorHandler::Severity::Warning);
        return;
    }

    QString keyPath = QFileDialog::getSaveFileName(this, tr("Save Private Key"), QDir::homePath(), fileFilter);
    if (keyPath.isEmpty()) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Key save canceled"), ForensicErrorHandler::Severity::Info);
        return;
    }
    if (!keyPath.endsWith(defaultExt)) {
        keyPath += defaultExt;
    }

    // Validazione del commento (usato solo per SSH)
    QString comment = commentEdit->text().trimmed();
    if (format == "SSH" && !validateComment(comment)) {
        errorHandler->handleError(this, tr("Generate Key"),
                                  tr("Invalid comment: must be alphanumeric, spaces, hyphens, underscores, or a valid email address"),
                                  ForensicErrorHandler::Severity::Warning);
        return;
    }

    // RAII per EVP_PKEY_CTX
    struct EVP_PKEY_CTXDeleter {
        void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
    };
    using EVP_PKEY_CTXPtr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTXDeleter>;

    // RAII per EVP_PKEY
    struct EVP_PKEYDeleter {
        void operator()(EVP_PKEY* pkey) const { EVP_PKEY_free(pkey); }
    };
    using EVP_PKEYPtr = std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter>;

    // RAII per BIO
    struct BIODeleter {
        void operator()(BIO* bio) const { BIO_free(bio); }
    };
    using BIOPtr = std::unique_ptr<BIO, BIODeleter>;

    // Generazione della chiave
    EVP_PKEY_CTXPtr ctx(nullptr);
    if (keyType == "RSA") {
        ctx.reset(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    } else if (keyType == "ECDSA") {
        ctx.reset(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    } else if (keyType == "Ed25519") {
        ctx.reset(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
    }

    if (!ctx) {
        char err_buf[256];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        errorHandler->handleError(this, tr("Generate Key"), tr("Failed to create EVP context: %1").arg(err_buf),
                                  ForensicErrorHandler::Severity::Critical);
        return;
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        char err_buf[256];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        errorHandler->handleError(this, tr("Generate Key"), tr("Failed to initialize keygen: %1").arg(err_buf),
                                  ForensicErrorHandler::Severity::Critical);
        return;
    }

    if (keyType == "RSA") {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), keyLength) <= 0) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to set RSA key length: %1").arg(err_buf),
                                      ForensicErrorHandler::Severity::Critical);
            return;
        }
    } else if (keyType == "ECDSA") {
        int curve_nid;
        if (keyLength == 256) curve_nid = NID_X9_62_prime256v1;
        else if (keyLength == 384) curve_nid = NID_secp384r1;
        else if (keyLength == 521) curve_nid = NID_secp521r1;
        else {
            errorHandler->handleError(this, tr("Generate Key"), tr("Unsupported ECDSA curve"), ForensicErrorHandler::Severity::Critical);
            return;
        }
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), curve_nid) <= 0) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to set ECDSA curve: %1").arg(err_buf),
                                      ForensicErrorHandler::Severity::Critical);
            return;
        }
    } // Ed25519 non richiede parametri aggiuntivi

    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0) {
        char err_buf[256];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        errorHandler->handleError(this, tr("Generate Key"), tr("Failed to generate %1 key: %2").arg(keyType, err_buf),
                                  ForensicErrorHandler::Severity::Critical);
        return;
    }
    EVP_PKEYPtr pkey(pkey_raw);

    // Apertura del file per la chiave privata
    QFile privateKeyFile(keyPath);
    if (!privateKeyFile.open(QIODevice::WriteOnly)) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Unable to open file: %1").arg(keyPath),
                                  ForensicErrorHandler::Severity::Critical);
        return;
    }

    FILE* privateKeyFp = fdopen(privateKeyFile.handle(), "wb"); // Nota: "wb" per DER (binario)
    if (!privateKeyFp) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Unable to open file descriptor: %1").arg(keyPath),
                                  ForensicErrorHandler::Severity::Critical);
        privateKeyFile.close();
        return;
    }

    // Scrittura della chiave privata
    QByteArray passwordBytes = password.toUtf8();
    if (format == "PEM") {
        if (!PEM_write_PrivateKey(privateKeyFp, pkey.get(), EVP_aes_256_cbc(),
                                  (unsigned char*)passwordBytes.constData(), passwordBytes.length(), nullptr, nullptr)) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write PEM private key: %1").arg(err_buf),
                                      ForensicErrorHandler::Severity::Critical);
            secureClear(passwordBytes);
            fclose(privateKeyFp);
            privateKeyFile.close();
            return;
        }
    } else if (format == "SSH") {
        BIOPtr bio(BIO_new(BIO_s_mem()));
        if (!bio) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to create BIO for SSH key: %1").arg(err_buf),
                                      ForensicErrorHandler::Severity::Critical);
            secureClear(passwordBytes);
            fclose(privateKeyFp);
            privateKeyFile.close();
            return;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        if (!PEM_write_bio_PrivateKey(bio.get(), pkey.get(), EVP_aes_256_cbc(),
                                      (unsigned char*)passwordBytes.constData(), passwordBytes.length(), nullptr, nullptr)) {
#else
        if (!PEM_write_bio_PrivateKey_traditional(bio.get(), pkey.get(), EVP_aes_256_cbc(),
                                                  (unsigned char*)passwordBytes.constData(), passwordBytes.length(), nullptr, nullptr)) {
#endif
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to convert to SSH private key: %1").arg(err_buf),
                                      ForensicErrorHandler::Severity::Critical);
            secureClear(passwordBytes);
            fclose(privateKeyFp);
            privateKeyFile.close();
            return;
        }

        char* bio_data;
        long bio_len = BIO_get_mem_data(bio.get(), &bio_data);
        if (fwrite(bio_data, 1, bio_len, privateKeyFp) != static_cast<size_t>(bio_len)) {
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write SSH private key to file"),
                                      ForensicErrorHandler::Severity::Critical);
            secureClear(passwordBytes);
            fclose(privateKeyFp);
            privateKeyFile.close();
            return;
        }
    } else if (format == "DER") {
        if (i2d_PrivateKey_fp(privateKeyFp, pkey.get()) <= 0) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write DER private key: %1").arg(err_buf),
                                      ForensicErrorHandler::Severity::Critical);
            secureClear(passwordBytes);
            fclose(privateKeyFp);
            privateKeyFile.close();
            return;
        }
    } else if (format == "PKCS#8") {
        if (!PEM_write_PKCS8PrivateKey(privateKeyFp, pkey.get(), EVP_aes_256_cbc(),
                                       (char*)passwordBytes.constData(), passwordBytes.length(), nullptr, nullptr)) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write PKCS#8 private key: %1").arg(err_buf),
                                      ForensicErrorHandler::Severity::Critical);
            secureClear(passwordBytes);
            fclose(privateKeyFp);
            privateKeyFile.close();
            return;
        }
    }

    secureClear(passwordBytes);
    fclose(privateKeyFp);
    if (!privateKeyFile.setPermissions(QFile::ReadOwner | QFile::WriteOwner)) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Failed to set permissions for %1").arg(keyPath),
                                  ForensicErrorHandler::Severity::Warning);
    }
    privateKeyFile.close();

    errorHandler->handleError(this, tr("Generate Key"), tr("Private key saved to %1 in %2 format").arg(keyPath, format),
                              ForensicErrorHandler::Severity::Info);
    errorHandler->logToAuditTrail(tr("Generate Key"),
                                  tr("Generated and saved %1-%2 key to %3 in %4 format").arg(keyType, QLocale().toString(keyLength), keyPath, format));

    // Scrittura della chiave pubblica
    QString publicKeyPath = keyPath + ".pub";
    QFile publicKeyFile(publicKeyPath);
    if (!publicKeyFile.open(QIODevice::WriteOnly)) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Unable to open public key file: %1").arg(publicKeyPath),
                                  ForensicErrorHandler::Severity::Warning);
        return;
    }

    FILE* publicKeyFp = fdopen(publicKeyFile.handle(), "wb"); // Nota: "wb" per DER
    if (!publicKeyFp) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Unable to open public key file descriptor: %1").arg(publicKeyPath),
                                  ForensicErrorHandler::Severity::Warning);
        publicKeyFile.close();
        return;
    }

    if (format == "PEM") {
        if (!PEM_write_PUBKEY(publicKeyFp, pkey.get())) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write PEM public key: %1").arg(err_buf),
                                      ForensicErrorHandler::Severity::Warning);
            fclose(publicKeyFp);
            publicKeyFile.close();
            return;
        }
    } else if (format == "SSH") {
        BIOPtr bio(BIO_new(BIO_s_mem()));
        if (!bio) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to create BIO for SSH public key: %1").arg(err_buf),
                                      ForensicErrorHandler::Severity::Warning);
            fclose(publicKeyFp);
            publicKeyFile.close();
            return;
        }

        if (!PEM_write_bio_PUBKEY(bio.get(), pkey.get())) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write public key: %1").arg(err_buf),
                                      ForensicErrorHandler::Severity::Warning);
            fclose(publicKeyFp);
            publicKeyFile.close();
            return;
        }

        QString sshComment = comment.isEmpty() ? QString("%1@keymanager").arg(m_username) : comment;
        char* bio_data;
        long bio_len = BIO_get_mem_data(bio.get(), &bio_data);
        QString sshPubKeyPrefix = keyType == "RSA" ? "ssh-rsa" : keyType == "ECDSA" ? "ecdsa-sha2-nistp" + QString::number(keyLength) : "ssh-ed25519";
        QString sshPubKey = QString("%1 %2 %3\n").arg(sshPubKeyPrefix, QString(QByteArray(bio_data, bio_len).toBase64()), sshComment);
        if (fwrite(sshPubKey.toUtf8().constData(), 1, sshPubKey.toUtf8().length(), publicKeyFp) != static_cast<size_t>(sshPubKey.toUtf8().length())) {
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write SSH public key to file"),
                                      ForensicErrorHandler::Severity::Warning);
            fclose(publicKeyFp);
            publicKeyFile.close();
            return;
        }
    } else if (format == "DER") {
        if (keyType == "Ed25519") {
            errorHandler->handleError(this, tr("Generate Key"),
                                      tr("DER format is not supported for Ed25519 public keys"),
                                      ForensicErrorHandler::Severity::Warning);
            fclose(publicKeyFp);
            publicKeyFile.close();
            return;
        }
        if (i2d_PUBKEY_fp(publicKeyFp, pkey.get()) <= 0) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write DER public key: %1").arg(err_buf),
                                      ForensicErrorHandler::Severity::Warning);
            fclose(publicKeyFp);
            publicKeyFile.close();
            return;
        }
    } else if (format == "PKCS#8") {
        if (keyType == "Ed25519") {
            errorHandler->handleError(this, tr("Generate Key"),
                                      tr("PKCS#8 format is not supported for Ed25519 public keys"),
                                      ForensicErrorHandler::Severity::Warning);
            fclose(publicKeyFp);
            publicKeyFile.close();
            return;
        }
        if (!PEM_write_PUBKEY(publicKeyFp, pkey.get())) {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            errorHandler->handleError(this, tr("Generate Key"), tr("Failed to write PKCS#8 public key: %1").arg(err_buf),
                                      ForensicErrorHandler::Severity::Warning);
            fclose(publicKeyFp);
            publicKeyFile.close();
            return;
        }
    }

    fclose(publicKeyFp);
    if (!publicKeyFile.setPermissions(QFile::ReadOwner | QFile::WriteOwner | QFile::ReadGroup | QFile::ReadOther)) {
        errorHandler->handleError(this, tr("Generate Key"), tr("Failed to set permissions for %1").arg(publicKeyPath),
                                  ForensicErrorHandler::Severity::Warning);
    }
    publicKeyFile.close();

    m_lastPublicKeyPath = publicKeyPath;
    errorHandler->handleError(this, tr("Generate Key"), tr("Public key saved to %1 in %2 format").arg(publicKeyPath, format),
                              ForensicErrorHandler::Severity::Info);
    errorHandler->logToAuditTrail(tr("Generate Key"),
                                  tr("Saved public key to %1 in %2 format with comment '%3'").arg(publicKeyPath, format, comment.isEmpty() ? tr("default") : comment));
}

void KeyManagerWindow::verifyKey() {
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
    privateKeyFile.close();
    BIOPtr bio(BIO_new_mem_buf(keyData.constData(), keyData.size()));
    if (!bio) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Failed to create BIO for key: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Critical);
        return;
    }

    // Attempt to read private key (supports both PEM and OpenSSH formats)
    QByteArray passwordBytes = password.toUtf8();
    EVP_PKEY *pkey_raw = nullptr;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    pkey_raw = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, (void*)passwordBytes.constData());
#else
    pkey_raw = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, (void*)passwordBytes.data());
#endif
    secureClear(passwordBytes);
    if (!pkey_raw) {
        errorHandler->handleError(this, tr("Verify Key"), tr("Invalid private key or wrong password: %1").arg(ERR_error_string(ERR_get_error(), nullptr)), ForensicErrorHandler::Severity::Warning);
        return;
    }
    EVP_PKEYPtr pkey(pkey_raw);

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

    QString keyFormat = keyPath.endsWith(".pem") ? "PEM" : "OpenSSH";
    errorHandler->handleError(this, tr("Verify Key"), tr("Private key verified successfully (%1 format)").arg(keyFormat), ForensicErrorHandler::Severity::Info);
    errorHandler->logToAuditTrail(tr("Verify Key"), tr("Successfully verified %1 key %2").arg(keyFormat, keyPath));
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
                errorHandler->logToAuditTrail(tr("Clear Log"), tr("Audit file cleared"));
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
    errorHandler->logToAuditTrail(tr("Window Closed"), tr("User %1 closed the application").arg(m_username));
    emit logoutRequested();
    event->accept();
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

    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(publicKeyContent);

    QString keyFormat = m_lastPublicKeyPath.endsWith(".pem.pub") ? "PEM" : "OpenSSH";
    errorHandler->handleError(this, tr("Copy Public Key"), tr("Public key copied to clipboard (%1 format)").arg(keyFormat), ForensicErrorHandler::Severity::Info);
    errorHandler->logToAuditTrail(tr("Copy Public Key"), tr("Copied public key from %1 (%2 format) to clipboard").arg(m_lastPublicKeyPath, keyFormat));
}

void KeyManagerWindow::changeLanguage(const QString &locale) {
    static QTranslator *translator = nullptr;
    if (translator) {
        QApplication::instance()->removeTranslator(translator);
        delete translator;
    }
    translator = new QTranslator;
    QString translationPath = QCoreApplication::applicationDirPath() + "/translations";
    if (translator->load("keymanager_" + locale, translationPath)) {
        QApplication::instance()->installTranslator(translator);
        errorHandler->logToAuditTrail(tr("Language Change"), tr("Changed language to %1").arg(locale));
        setupUi(); // Rebuild UI to apply translations
        if (QLocale(locale).textDirection() == Qt::RightToLeft) {
            QApplication::setLayoutDirection(Qt::RightToLeft);
        } else {
            QApplication::setLayoutDirection(Qt::LeftToRight);
        }
    } else {
        errorHandler->handleError(this, tr("Language Change"), tr("Failed to load translation for %1").arg(locale), ForensicErrorHandler::Severity::Warning);
        delete translator;
        translator = nullptr;
    }
}
