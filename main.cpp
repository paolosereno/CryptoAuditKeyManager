#include <QApplication>
#include <QCommandLineParser>
#include <QTranslator>
#include <QMessageBox>
#include <QDir>
#include <QInputDialog>
#include <QLineEdit>
#include <QRegularExpression>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include "keymanagerwindow.h"
#include "database.h"
#include "forensicerrorhandler.h"

// Helper function to securely clear sensitive data
static void secureClear(QByteArray &data) {
    std::fill(data.begin(), data.end(), 0);
}

// Initialize OpenSSL with version compatibility
void initializeOpenSSL() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT | OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
#endif
}

// Clean up OpenSSL
void cleanupOpenSSL() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    ERR_free_strings();
#else
    OPENSSL_cleanup();
#endif
}

bool isValidUsername(const QString &username) {
    QRegularExpression regex("^[a-zA-Z0-9_]{3,50}$");
    return regex.match(username).hasMatch();
}

// Function to handle the authentication process
bool authenticateUser(Database &db, ForensicErrorHandler &errorHandler, QString &username) {
    int maxAttempts = 3;
    int attempts = 0;
    bool authenticated = false;

    while (attempts < maxAttempts && !authenticated) {
        bool ok;
        username = QInputDialog::getText(nullptr, QObject::tr("Login"), QObject::tr("Username:"), QLineEdit::Normal, QString(), &ok);
        if (!ok || username.isEmpty()) {
            QMessageBox::critical(nullptr, QObject::tr("Authentication Failed"), QObject::tr("Username is required."));
            errorHandler.logToAuditTrail(QObject::tr("Login Attempt"), QObject::tr("Failed: Username not provided"));
            return false;
        }

        if (!isValidUsername(username)) {
            QMessageBox::critical(nullptr, QObject::tr("Authentication Failed"), QObject::tr("Invalid username format: must be 3-50 alphanumeric characters or underscores."));
            errorHandler.logToAuditTrail(QObject::tr("Login Attempt"), QObject::tr("Failed: Invalid username format"));
            return false;
        }

        if (db.isAccountLocked(username)) {
            QMessageBox::critical(nullptr, QObject::tr("Account Locked"), QObject::tr("Account is temporarily locked. Try again later."));
            errorHandler.logToAuditTrail(QObject::tr("Login Attempt"), QObject::tr("Account locked for user: %1").arg(username));
            return false;
        }

        QString password = QInputDialog::getText(nullptr, QObject::tr("Login"), QObject::tr("Password:"), QLineEdit::Password, QString(), &ok);
        if (!ok) {
            QMessageBox::critical(nullptr, QObject::tr("Authentication Failed"), QObject::tr("Password is required."));
            errorHandler.logToAuditTrail(QObject::tr("Login Attempt"), QObject::tr("Failed: Password not provided for user %1").arg(username));
            return false;
        }

        QByteArray passwordBytes = password.toUtf8();
        if (db.authenticateUser(username, password)) {
            authenticated = true;
            db.logLoginAttempt(username, true);
            errorHandler.logToAuditTrail(QObject::tr("Login Attempt"), QObject::tr("Success: User %1 authenticated").arg(username));
        } else {
            attempts++;
            db.logLoginAttempt(username, false);
            errorHandler.logToAuditTrail(QObject::tr("Login Attempt"), QObject::tr("Failed: Invalid credentials for user %1").arg(username));
            QMessageBox::critical(nullptr, QObject::tr("Authentication Failed"),
                                  QObject::tr("%n attempt(s) remaining.", "", maxAttempts - attempts));
        }
        secureClear(passwordBytes); // Securely clear password
    }

    return authenticated;
}

int main(int argc, char *argv[]) {
    // Initialize OpenSSL
    initializeOpenSSL();

    QApplication app(argc, argv);

    // Configure command line parser
    QCommandLineParser parser;
    parser.setApplicationDescription(QObject::tr("Crypto Audit Key Manager"));
    parser.addHelpOption();
    QCommandLineOption auditFileOption(QStringList() << "a" << "audit-file",
                                       QObject::tr("Path to audit file"),
                                       QObject::tr("auditfile"),
                                       QDir::homePath() + "/keymanager_audit.log");
    parser.addOption(auditFileOption);
    parser.process(app);

    // Read and validate audit file path
    QString auditFilePath = parser.value(auditFileOption);
    QFileInfo auditFileInfo(auditFilePath);
    if (auditFileInfo.exists() && !auditFileInfo.isWritable()) {
        QMessageBox::critical(nullptr, QObject::tr("Invalid Audit File"), QObject::tr("Audit file path is not writable: %1").arg(auditFilePath));
        cleanupOpenSSL();
        return 1;
    }

    // Configure translator for internationalization
    QTranslator translator;
    QString locale = QLocale::system().name();
    QString translationPath = QCoreApplication::applicationDirPath() + "/translations";
    if (!translator.load("keymanager_" + locale, translationPath)) {
        qDebug() << "Failed to load translation for locale:" << locale;
        // Fallback to English
        if (!translator.load("keymanager_en_US", translationPath)) {
            qDebug() << "Failed to load fallback translation (en_US)";
        }
    }
    app.installTranslator(&translator);

    // Handle RTL languages
    if (QLocale(locale).textDirection() == Qt::RightToLeft) {
        QApplication::setLayoutDirection(Qt::RightToLeft);
    } else {
        QApplication::setLayoutDirection(Qt::LeftToRight);
    }

    // Initialize database
    ForensicErrorHandler tempErrorHandler(auditFilePath, "system");
    Database db(QDir::homePath() + "/users.db", &tempErrorHandler);
    if (!db.initialize()) {
        QMessageBox::critical(nullptr, QObject::tr("Database Error"), QObject::tr("Failed to initialize database."));
        tempErrorHandler.logToAuditTrail(QObject::tr("Initialization"), QObject::tr("Failed to initialize database"));
        cleanupOpenSSL();
        return 1;
    }

    // Check if the database is empty and create a new user
    if (!db.hasUsers()) {
        bool ok;
        QString username = QInputDialog::getText(nullptr, QObject::tr("First Setup"), QObject::tr("Enter new admin username:"), QLineEdit::Normal, QString(), &ok);
        if (!ok || username.isEmpty()) {
            QMessageBox::critical(nullptr, QObject::tr("Setup Error"), QObject::tr("Username is required."));
            tempErrorHandler.logToAuditTrail(QObject::tr("Setup Attempt"), QObject::tr("Failed: Username not provided"));
            cleanupOpenSSL();
            return 1;
        }

        if (!isValidUsername(username)) {
            QMessageBox::critical(nullptr, QObject::tr("Setup Error"), QObject::tr("Invalid username format: must be 3-50 alphanumeric characters or underscores."));
            tempErrorHandler.logToAuditTrail(QObject::tr("Setup Attempt"), QObject::tr("Failed: Invalid username format"));
            cleanupOpenSSL();
            return 1;
        }

        QString password = QInputDialog::getText(nullptr, QObject::tr("First Setup"), QObject::tr("Enter new admin password:"), QLineEdit::Password, QString(), &ok);
        if (!ok || password.isEmpty()) {
            QMessageBox::critical(nullptr, QObject::tr("Setup Error"), QObject::tr("Password is required."));
            tempErrorHandler.logToAuditTrail(QObject::tr("Setup Attempt"), QObject::tr("Failed: Password not provided for user %1").arg(username));
            cleanupOpenSSL();
            return 1;
        }

        // Validate password
        QRegularExpression passwordRegex("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[!@#$%^&*_])[A-Za-z\\d!@#$%^&*_]{8,}$");
        if (!passwordRegex.match(password).hasMatch()) {
            QMessageBox::critical(nullptr, QObject::tr("Setup Error"),
                                  QObject::tr("Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters."));
            tempErrorHandler.logToAuditTrail(QObject::tr("Setup Attempt"), QObject::tr("Failed: Invalid password for user %1").arg(username));
            cleanupOpenSSL();
            return 1;
        }

        QByteArray passwordBytes = password.toUtf8();
        // Register the new user
        if (!db.registerUser(username, password)) {
            QMessageBox::critical(nullptr, QObject::tr("Setup Error"), QObject::tr("Failed to create new admin user."));
            tempErrorHandler.logToAuditTrail(QObject::tr("Setup Attempt"), QObject::tr("Failed: Could not register user %1").arg(username));
            secureClear(passwordBytes); // Securely clear password
            cleanupOpenSSL();
            return 1;
        }

        // Verify that the new user can authenticate
        if (db.authenticateUser(username, password)) {
            // Remove the default admin user if it exists
            if (db.userExists("admin")) {
                if (db.removeUser("admin")) {
                    tempErrorHandler.logToAuditTrail(QObject::tr("Setup"), QObject::tr("Successfully created user %1 and removed default admin").arg(username));
                    QMessageBox::information(nullptr, QObject::tr("Setup Complete"), QObject::tr("New admin user %1 created successfully.").arg(username));
                } else {
                    QMessageBox::warning(nullptr, QObject::tr("Setup Warning"), QObject::tr("New user created, but failed to remove default admin."));
                    tempErrorHandler.logToAuditTrail(QObject::tr("Setup"), QObject::tr("Warning: Failed to remove default admin after creating user %1").arg(username));
                }
            } else {
                tempErrorHandler.logToAuditTrail(QObject::tr("Setup"), QObject::tr("Successfully created user %1; no default admin found").arg(username));
                QMessageBox::information(nullptr, QObject::tr("Setup Complete"), QObject::tr("New admin user %1 created successfully.").arg(username));
            }
        } else {
            QMessageBox::critical(nullptr, QObject::tr("Setup Error"), QObject::tr("Failed to verify new admin user."));
            tempErrorHandler.logToAuditTrail(QObject::tr("Setup Attempt"), QObject::tr("Failed: Could not verify new user %1").arg(username));
            secureClear(passwordBytes); // Securely clear password
            cleanupOpenSSL();
            return 1;
        }
        secureClear(passwordBytes); // Securely clear password
    }

    // Main authentication loop
    bool continueRunning = true;
    while (continueRunning) {
        QString username;
        if (!authenticateUser(db, tempErrorHandler, username)) {
            continueRunning = false;
            break;
        }

        KeyManagerWindow window(auditFilePath, username);
        window.show();

        // Connection to handle logout
        QObject::connect(&window, &KeyManagerWindow::logoutRequested, [&]() {
            continueRunning = false;
        });

        if (app.exec() != 0) {
            continueRunning = false;
        }
    }

    // Clean up OpenSSL
    cleanupOpenSSL();
    return 0;
}
