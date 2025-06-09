#include "database.h"
#include <QSqlQuery>
#include <QSqlError>
#include <QDebug>
#include <QDir>
#include <QRegularExpression>
#include <QThread>
#include <openssl/opensslv.h>

// Helper function to securely clear sensitive data
static void secureClear(QByteArray &data) {
    std::fill(data.begin(), data.end(), 0);
}

Database::Database(const QString &dbPath, ForensicErrorHandler *errorHandler, QObject *parent)
    : QObject(parent), m_dbPath(dbPath), m_errorHandler(errorHandler) {
    // Generate unique connection name to avoid conflicts
    m_connectionName = QString("users_connection_%1").arg(quintptr(this), 0, 16);
}

Database::~Database() {
    closeDatabase();
}

bool Database::initialize() {
    if (!openDatabase()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to open database: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        return false;
    }
    bool success = createTables();
    if (!success) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to initialize tables"), ForensicErrorHandler::Severity::Critical);
    }
    closeDatabase();
    return success;
}

bool Database::openDatabase() {
    if (m_db.isOpen()) return true;

    m_db = QSqlDatabase::addDatabase("QSQLITE", m_connectionName);
    m_db.setDatabaseName(m_dbPath);
    int retries = 3;
    while (retries > 0) {
        if (m_db.open()) return true;
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to open database: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Warning);
        QThread::msleep(100); // Wait before retry
        retries--;
    }
    m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to open database after retries"), ForensicErrorHandler::Severity::Critical);
    return false;
}

void Database::closeDatabase() {
    if (m_db.isOpen()) {
        m_db.close();
    }
    if (QSqlDatabase::contains(m_connectionName)) {
        QSqlDatabase::removeDatabase(m_connectionName);
    }
}

bool Database::createTables() {
    if (!m_db.isOpen() && !openDatabase()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Cannot create tables: database not open"), ForensicErrorHandler::Severity::Critical);
        return false;
    }

    if (!m_db.transaction()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to start transaction"), ForensicErrorHandler::Severity::Critical);
        closeDatabase();
        return false;
    }

    QSqlQuery query(m_db);
    bool success = query.exec(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "password_hash TEXT NOT NULL, "
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        );
    if (!success) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to create users table: %1").arg(query.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    success = query.exec("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)");
    if (!success) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to create users index: %1").arg(query.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    success = query.exec(
        "CREATE TABLE IF NOT EXISTS login_attempts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT NOT NULL, "
        "attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
        "success BOOLEAN NOT NULL)"
        );
    if (!success) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to create login_attempts table: %1").arg(query.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    success = query.exec("CREATE INDEX IF NOT EXISTS idx_login_attempts_username_time ON login_attempts(username, attempt_time)");
    if (!success) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to create login_attempts index: %1").arg(query.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    if (!m_db.commit()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to commit transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    return true;
}

bool Database::isValidUsername(const QString &username) const {
    static const QStringList reservedKeywords = {"SELECT", "DROP", "INSERT", "UPDATE", "DELETE"};
    if (username.isEmpty() || reservedKeywords.contains(username, Qt::CaseInsensitive)) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Invalid or reserved username"), ForensicErrorHandler::Severity::Warning);
        return false;
    }
    QRegularExpression regex("^[a-zA-Z0-9_]{3,50}$");
    if (!regex.match(username).hasMatch()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Username must be 3-50 alphanumeric characters or underscores"), ForensicErrorHandler::Severity::Warning);
        return false;
    }
    return true;
}

bool Database::registerUser(const QString &username, const QString &password) {
    if (!isValidUsername(username)) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Invalid username format: must be 3-50 alphanumeric characters or underscores"), ForensicErrorHandler::Severity::Warning);
        return false;
    }

    // Validazione della password
    if (!SecurityUtils::validatePassword(password, m_errorHandler)) {
        return false;
    }

    if (!openDatabase()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to open database for registration"), ForensicErrorHandler::Severity::Critical);
        return false;
    }

    if (!m_db.transaction()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to start transaction"), ForensicErrorHandler::Severity::Critical);
        closeDatabase();
        return false;
    }

    // Argon2 parameters
    const size_t saltLen = 16;
    const size_t hashLen = 32;
    const uint32_t t_cost = 4; // Iterations
    const uint32_t m_cost = 1 << 16; // Memory (64MB)
    const uint32_t parallelism = 1;

    // Generate random salt
    unsigned char salt[saltLen];
    bool randSuccess = false;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    randSuccess = (RAND_bytes(salt, saltLen) == 1);
#else
    randSuccess = (RAND_pseudo_bytes(salt, saltLen) >= 0);
#endif
    if (!randSuccess) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to generate random salt"), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    // Generate password hash
    unsigned char hash[hashLen];
    QByteArray passwordBytes = password.toUtf8();
    int result = argon2id_hash_raw(t_cost, m_cost, parallelism,
                                   passwordBytes.constData(), passwordBytes.length(),
                                   salt, saltLen, hash, hashLen);
    secureClear(passwordBytes); // Securely clear password
    if (result != ARGON2_OK) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Argon2 hashing failed: %1").arg(result), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    // Combine salt and hash for storage
    QString hashStr = QString(QByteArray((char*)hash, hashLen).toBase64());
    QString saltStr = QString(QByteArray((char*)salt, saltLen).toBase64());
    QString storedHash = QString("%1$%2").arg(saltStr, hashStr);

    // Save user to database
    QSqlQuery query(m_db);
    query.prepare("INSERT INTO users (username, password_hash) VALUES (:username, :hash)");
    query.bindValue(":username", username);
    query.bindValue(":hash", storedHash);
    bool success = query.exec();
    if (!success) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to register user: %1").arg(query.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    if (!m_db.commit()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to commit transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    closeDatabase();
    return true;
}

bool Database::authenticateUser(const QString &username, const QString &password) {
    if (!isValidUsername(username)) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Invalid username format"), ForensicErrorHandler::Severity::Warning);
        return false;
    }

    if (!openDatabase()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to open database for authentication"), ForensicErrorHandler::Severity::Critical);
        return false;
    }

    if (!m_db.transaction()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to start transaction"), ForensicErrorHandler::Severity::Critical);
        closeDatabase();
        return false;
    }

    // Retrieve stored hash
    QSqlQuery query(m_db);
    query.prepare("SELECT password_hash FROM users WHERE username = :username");
    query.bindValue(":username", username);
    if (!query.exec() || !query.next()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("User not found or query failed: %1").arg(query.lastError().text()), ForensicErrorHandler::Severity::Warning);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    QString storedHash = query.value(0).toString();
    QStringList parts = storedHash.split('$');
    if (parts.size() != 2) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Invalid stored hash format"), ForensicErrorHandler::Severity::Warning);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    // Extract salt and hash
    QByteArray salt = QByteArray::fromBase64(parts[0].toUtf8());
    QByteArray expectedHash = QByteArray::fromBase64(parts[1].toUtf8());

    // Argon2 parameters
    const uint32_t t_cost = 4;
    const uint32_t m_cost = 1 << 16;
    const uint32_t parallelism = 1;

    // Compute hash of provided password
    unsigned char computedHash[expectedHash.length()];
    QByteArray passwordBytes = password.toUtf8();
    int result = argon2id_hash_raw(t_cost, m_cost, parallelism,
                                   passwordBytes.constData(), passwordBytes.length(),
                                   (unsigned char*)salt.constData(), salt.length(),
                                   computedHash, expectedHash.length());
    secureClear(passwordBytes); // Securely clear password
    if (result != ARGON2_OK) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Argon2 verification failed: %1").arg(result), ForensicErrorHandler::Severity::Warning);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    // Compare hashes securely
    bool match = (CRYPTO_memcmp(computedHash, expectedHash.constData(), expectedHash.length()) == 0);

    if (!m_db.commit()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to commit transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    closeDatabase();
    return match;
}

bool Database::isAccountLocked(const QString &username) {
    if (!isValidUsername(username)) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Invalid username format"), ForensicErrorHandler::Severity::Warning);
        return true; // Consider locked for invalid input
    }

    if (!openDatabase()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to open database for account lock check"), ForensicErrorHandler::Severity::Critical);
        return true; // Consider locked in case of error
    }

    if (!m_db.transaction()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to start transaction"), ForensicErrorHandler::Severity::Critical);
        closeDatabase();
        return true;
    }

    QSqlQuery query(m_db);
    query.prepare("SELECT COUNT(*) FROM login_attempts WHERE username = :username AND success = 0 AND attempt_time > datetime('now', '-5 minutes')");
    query.bindValue(":username", username);
    bool success = query.exec() && query.next();
    bool locked = false;
    if (success) {
        int failedAttempts = query.value(0).toInt();
        locked = failedAttempts >= 3;
    } else {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to check account lock status: %1").arg(query.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return true;
    }

    if (!m_db.commit()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to commit transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return true;
    }

    closeDatabase();
    return locked;
}

void Database::logLoginAttempt(const QString &username, bool success) {
    if (!isValidUsername(username)) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Invalid username format for login attempt logging"), ForensicErrorHandler::Severity::Warning);
        return;
    }

    if (!openDatabase()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to open database for login attempt logging"), ForensicErrorHandler::Severity::Warning);
        return;
    }

    if (!m_db.transaction()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to start transaction"), ForensicErrorHandler::Severity::Warning);
        closeDatabase();
        return;
    }

    QSqlQuery query(m_db);
    query.prepare("INSERT INTO login_attempts (username, success) VALUES (:username, :success)");
    query.bindValue(":username", username);
    query.bindValue(":success", success);
    if (!query.exec()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to log login attempt: %1").arg(query.lastError().text()), ForensicErrorHandler::Severity::Warning);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return;
    }

    if (!m_db.commit()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to commit transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Warning);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return;
    }

    closeDatabase();
}

void Database::cleanupLoginAttempts() {
    if (!openDatabase()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to open database for login attempts cleanup"), ForensicErrorHandler::Severity::Warning);
        return;
    }

    if (!m_db.transaction()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to start transaction"), ForensicErrorHandler::Severity::Warning);
        closeDatabase();
        return;
    }

    QSqlQuery query(m_db);
    query.prepare("DELETE FROM login_attempts WHERE attempt_time < datetime('now', '-1 day')");
    if (!query.exec()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to clean up login attempts: %1").arg(query.lastError().text()), ForensicErrorHandler::Severity::Warning);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return;
    }

    if (!m_db.commit()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to commit transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Warning);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return;
    }

    closeDatabase();
}

bool Database::hasUsers() {
    if (!openDatabase()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to open database to check for users"), ForensicErrorHandler::Severity::Critical);
        return false;
    }

    if (!m_db.transaction()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to start transaction"), ForensicErrorHandler::Severity::Critical);
        closeDatabase();
        return false;
    }

    QSqlQuery query(m_db);
    bool success = query.exec("SELECT COUNT(*) FROM users");
    bool hasUsers = false;
    if (success && query.next()) {
        int count = query.value(0).toInt();
        hasUsers = count > 0;
    } else {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to check for users: %1").arg(query.lastError().text()), ForensicErrorHandler::Severity::Warning);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    if (!m_db.commit()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to commit transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    closeDatabase();
    return hasUsers;
}

bool Database::removeUser(const QString &username) {
    if (!isValidUsername(username)) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Invalid username format"), ForensicErrorHandler::Severity::Warning);
        return false;
    }

    if (!openDatabase()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to open database to remove user"), ForensicErrorHandler::Severity::Critical);
        return false;
    }

    if (!m_db.transaction()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to start transaction"), ForensicErrorHandler::Severity::Critical);
        closeDatabase();
        return false;
    }

    QSqlQuery query(m_db);
    query.prepare("DELETE FROM users WHERE username = :username");
    query.bindValue(":username", username);
    bool success = query.exec();
    if (!success) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to remove user: %1").arg(query.lastError().text()), ForensicErrorHandler::Severity::Warning);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    if (!m_db.commit()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to commit transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    closeDatabase();
    return true;
}

bool Database::userExists(const QString &username) {
    if (!isValidUsername(username)) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Invalid username format"), ForensicErrorHandler::Severity::Warning);
        return false;
    }

    if (!openDatabase()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to open database to check user existence"), ForensicErrorHandler::Severity::Critical);
        return false;
    }

    if (!m_db.transaction()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to start transaction"), ForensicErrorHandler::Severity::Critical);
        closeDatabase();
        return false;
    }

    QSqlQuery query(m_db);
    query.prepare("SELECT COUNT(*) FROM users WHERE username = :username");
    query.bindValue(":username", username);
    bool exists = false;
    if (query.exec() && query.next()) {
        int count = query.value(0).toInt();
        exists = count > 0;
    } else {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to check if user exists: %1").arg(query.lastError().text()), ForensicErrorHandler::Severity::Warning);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    if (!m_db.commit()) {
        m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to commit transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        if (!m_db.rollback()) {
            m_errorHandler->handleError(nullptr, tr("Database"), tr("Failed to rollback transaction: %1").arg(m_db.lastError().text()), ForensicErrorHandler::Severity::Critical);
        }
        closeDatabase();
        return false;
    }

    closeDatabase();
    return exists;
}
