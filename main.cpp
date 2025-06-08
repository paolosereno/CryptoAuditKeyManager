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
#include "keymanagerwindow.h"
#include "database.h"
#include "forensicerrorhandler.h"

// Funzione per gestire il processo di autenticazione
bool authenticateUser(Database &db, ForensicErrorHandler &errorHandler, QString &username) {
    int maxAttempts = 3;
    int attempts = 0;
    bool authenticated = false;

    while (attempts < maxAttempts && !authenticated) {
        bool ok;
        username = QInputDialog::getText(nullptr, QObject::tr("Login"), QObject::tr("Username:"), QLineEdit::Normal, QString(), &ok);
        if (!ok || username.isEmpty()) {
            QMessageBox::critical(nullptr, QObject::tr("Authentication Failed"), QObject::tr("Username is required."));
            errorHandler.logToAuditTrail("Login Attempt", QString("Failed: Username not provided"));
            return false;
        }

        if (db.isAccountLocked(username)) {
            QMessageBox::critical(nullptr, QObject::tr("Account Locked"), QObject::tr("Account is temporarily locked. Try again later."));
            errorHandler.logToAuditTrail("Login Attempt", QString("Account locked for user: %1").arg(username));
            return false;
        }

        QString password = QInputDialog::getText(nullptr, QObject::tr("Login"), QObject::tr("Password:"), QLineEdit::Password, QString(), &ok);
        if (!ok) {
            QMessageBox::critical(nullptr, QObject::tr("Authentication Failed"), QObject::tr("Password is required."));
            errorHandler.logToAuditTrail("Login Attempt", QString("Failed: Password not provided for user %1").arg(username));
            return false;
        }

        if (db.authenticateUser(username, password)) {
            authenticated = true;
            db.logLoginAttempt(username, true);
            errorHandler.logToAuditTrail("Login Attempt", QString("Success: User %1 authenticated").arg(username));
        } else {
            attempts++;
            db.logLoginAttempt(username, false);
            errorHandler.logToAuditTrail("Login Attempt", QString("Failed: Invalid credentials for user %1").arg(username));
            QMessageBox::critical(nullptr, QObject::tr("Authentication Failed"),
                                  QObject::tr("Invalid credentials. %1 attempts remaining.").arg(maxAttempts - attempts));
        }
    }

    return authenticated;
}

int main(int argc, char *argv[]) {
    // Initialize OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT | OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);

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
        OPENSSL_cleanup();
        return 1;
    }

    // Configure translator for internationalization
    QTranslator translator;
    QString locale = QLocale::system().name();
    QString translationPath = QCoreApplication::applicationDirPath() + "/translations";
    if (translator.load("keymanager_" + locale, translationPath)) {
        app.installTranslator(&translator);
    } else {
        qDebug() << "Failed to load translation for locale:" << locale;
    }

    // Initialize database
    Database db(QDir::homePath() + "/users.db");
    if (!db.initialize()) {
        QMessageBox::critical(nullptr, QObject::tr("Database Error"), QObject::tr("Failed to initialize database."));
        OPENSSL_cleanup();
        return 1;
    }

    ForensicErrorHandler tempErrorHandler(auditFilePath, "system");

    // Check if the database is empty and create a new user
    if (!db.hasUsers()) {
        bool ok;
        QString username = QInputDialog::getText(nullptr, QObject::tr("First Setup"), QObject::tr("Enter new admin username:"), QLineEdit::Normal, QString(), &ok);
        if (!ok || username.isEmpty()) {
            QMessageBox::critical(nullptr, QObject::tr("Setup Error"), QObject::tr("Username is required."));
            tempErrorHandler.logToAuditTrail("Setup Attempt", "Failed: Username not provided");
            OPENSSL_cleanup();
            return 1;
        }

        QString password = QInputDialog::getText(nullptr, QObject::tr("First Setup"), QObject::tr("Enter new admin password:"), QLineEdit::Password, QString(), &ok);
        if (!ok || password.isEmpty()) {
            QMessageBox::critical(nullptr, QObject::tr("Setup Error"), QObject::tr("Password is required."));
            tempErrorHandler.logToAuditTrail("Setup Attempt", QString("Failed: Password not provided for user %1").arg(username));
            OPENSSL_cleanup();
            return 1;
        }

        // Validate password
        QRegularExpression passwordRegex("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[!@#$%^&*_])[A-Za-z\\d!@#$%^&*_]{8,}$");
        if (!passwordRegex.match(password).hasMatch()) {
            QMessageBox::critical(nullptr, QObject::tr("Setup Error"),
                                  QObject::tr("Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters."));
            tempErrorHandler.logToAuditTrail("Setup Attempt", QString("Failed: Invalid password for user %1").arg(username));
            OPENSSL_cleanup();
            return 1;
        }

        // Register the new user
        if (!db.registerUser(username, password)) {
            QMessageBox::critical(nullptr, QObject::tr("Setup Error"), QObject::tr("Failed to create new admin user."));
            tempErrorHandler.logToAuditTrail("Setup Attempt", QString("Failed: Could not register user %1").arg(username));
            OPENSSL_cleanup();
            return 1;
        }

        // Verify that the new user can authenticate
        if (db.authenticateUser(username, password)) {
            // Remove the default admin user if it exists
            if (db.userExists("admin")) {
                if (db.removeUser("admin")) {
                    tempErrorHandler.logToAuditTrail("Setup", QString("Successfully created user %1 and removed default admin").arg(username));
                    QMessageBox::information(nullptr, QObject::tr("Setup Complete"), QObject::tr("New admin user %1 created successfully.").arg(username));
                } else {
                    QMessageBox::warning(nullptr, QObject::tr("Setup Warning"), QObject::tr("New user created, but failed to remove default admin."));
                    tempErrorHandler.logToAuditTrail("Setup", QString("Warning: Failed to remove default admin after creating user %1").arg(username));
                }
            } else {
                tempErrorHandler.logToAuditTrail("Setup", QString("Successfully created user %1; no default admin found").arg(username));
                QMessageBox::information(nullptr, QObject::tr("Setup Complete"), QObject::tr("New admin user %1 created successfully.").arg(username));
            }
        } else {
            QMessageBox::critical(nullptr, QObject::tr("Setup Error"), QObject::tr("Failed to verify new admin user."));
            tempErrorHandler.logToAuditTrail("Setup Attempt", QString("Failed: Could not verify new user %1").arg(username));
            OPENSSL_cleanup();
            return 1;
        }
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

        // Connessione per gestire il logout
        QObject::connect(&window, &KeyManagerWindow::logoutRequested, [&]() {
            continueRunning = false; // Continua il ciclo per un nuovo login
        });

        // Esegui l'applicazione e verifica se l'utente ha chiuso la finestra
        if (app.exec() != 0) {
            continueRunning = false; // Esci se l'applicazione viene chiusa manualmente
        }
    }

    // Clean up OpenSSL
    OPENSSL_cleanup();
    return 0;
}
