#include "database.h"
#include <QSqlQuery>
#include <QSqlError>
#include <QDebug>
#include <QDir>

Database::Database(const QString &dbPath, QObject *parent)
    : QObject(parent), m_dbPath(dbPath) {
}

Database::~Database() {
    closeDatabase();
}

bool Database::initialize() {
    if (!openDatabase()) {
        qWarning() << "Failed to open database:" << m_db.lastError().text();
        return false;
    }
    bool success = createTables();
    closeDatabase();
    return success;
}

bool Database::openDatabase() {
    m_db = QSqlDatabase::addDatabase("QSQLITE", "users_connection");
    m_db.setDatabaseName(m_dbPath);
    if (!m_db.open()) {
        qWarning() << "Database error:" << m_db.lastError().text();
        return false;
    }
    return true;
}

void Database::closeDatabase() {
    if (m_db.isOpen()) {
        m_db.close();
    }
    QSqlDatabase::removeDatabase("users_connection");
}

bool Database::createTables() {
    if (!openDatabase()) return false;

    QSqlQuery query(m_db);
    // Create users table
    bool success = query.exec(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "password_hash TEXT NOT NULL, "
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        );
    if (!success) {
        qWarning() << "Failed to create users table:" << query.lastError().text();
        closeDatabase();
        return false;
    }

    // Create login_attempts table
    success = query.exec(
        "CREATE TABLE IF NOT EXISTS login_attempts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT NOT NULL, "
        "attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
        "success BOOLEAN NOT NULL)"
        );
    if (!success) {
        qWarning() << "Failed to create login_attempts table:" << query.lastError().text();
        closeDatabase();
        return false;
    }

    closeDatabase();
    return true;
}

bool Database::registerUser(const QString &username, const QString &password) {
    if (!openDatabase()) return false;

    // Argon2 parameters
    const size_t saltLen = 16;
    const size_t hashLen = 32;
    const uint32_t t_cost = 4; // Iterations
    const uint32_t m_cost = 1 << 16; // Memory (64MB)
    const uint32_t parallelism = 1;

    // Generate random salt
    unsigned char salt[saltLen];
    if (RAND_bytes(salt, saltLen) != 1) {
        qWarning() << "Failed to generate random salt";
        closeDatabase();
        return false;
    }

    // Generate password hash
    unsigned char hash[hashLen];
    QByteArray passwordBytes = password.toUtf8();
    int result = argon2id_hash_raw(t_cost, m_cost, parallelism,
                                   passwordBytes.constData(), passwordBytes.length(),
                                   salt, saltLen, hash, hashLen);
    if (result != ARGON2_OK) {
        qWarning() << "Argon2 hashing failed:" << result;
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
        qWarning() << "Failed to register user:" << query.lastError().text();
    }

    closeDatabase();
    return success;
}

bool Database::authenticateUser(const QString &username, const QString &password) {
    if (!openDatabase()) return false;

    // Retrieve stored hash
    QSqlQuery query(m_db);
    query.prepare("SELECT password_hash FROM users WHERE username = :username");
    query.bindValue(":username", username);
    if (!query.exec() || !query.next()) {
        qWarning() << "User not found or query failed:" << query.lastError().text();
        closeDatabase();
        return false;
    }

    QString storedHash = query.value(0).toString();
    QStringList parts = storedHash.split('$');
    if (parts.size() != 2) {
        qWarning() << "Invalid stored hash format";
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
    if (result != ARGON2_OK) {
        qWarning() << "Argon2 verification failed:" << result;
        closeDatabase();
        return false;
    }

    // Compare hashes securely
    bool match = (CRYPTO_memcmp(computedHash, expectedHash.constData(), expectedHash.length()) == 0);
    closeDatabase();
    return match;
}

bool Database::isAccountLocked(const QString &username) {
    if (!openDatabase()) return true; // Consider locked in case of error

    QSqlQuery query(m_db);
    query.prepare("SELECT COUNT(*) FROM login_attempts WHERE username = :username AND success = 0 AND attempt_time > datetime('now', '-5 minutes')");
    query.bindValue(":username", username);
    if (query.exec() && query.next()) {
        int failedAttempts = query.value(0).toInt();
        closeDatabase();
        return failedAttempts >= 3;
    }

    closeDatabase();
    return false;
}

void Database::logLoginAttempt(const QString &username, bool success) {
    if (!openDatabase()) return;

    QSqlQuery query(m_db);
    query.prepare("INSERT INTO login_attempts (username, success) VALUES (:username, :success)");
    query.bindValue(":username", username);
    query.bindValue(":success", success);
    if (!query.exec()) {
        qWarning() << "Failed to log login attempt:" << query.lastError().text();
    }

    closeDatabase();
}

bool Database::hasUsers() {
    if (!openDatabase()) return false;

    QSqlQuery query(m_db);
    bool success = query.exec("SELECT COUNT(*) FROM users");
    if (success && query.next()) {
        int count = query.value(0).toInt();
        closeDatabase();
        return count > 0;
    }

    qWarning() << "Failed to check for users:" << query.lastError().text();
    closeDatabase();
    return false;
}

bool Database::removeUser(const QString &username) {
    if (!openDatabase()) return false;

    QSqlQuery query(m_db);
    query.prepare("DELETE FROM users WHERE username = :username");
    query.bindValue(":username", username);
    bool success = query.exec();
    if (!success) {
        qWarning() << "Failed to remove user:" << query.lastError().text();
    }

    closeDatabase();
    return success;
}

bool Database::userExists(const QString &username) {
    if (!openDatabase()) return false;

    QSqlQuery query(m_db);
    query.prepare("SELECT COUNT(*) FROM users WHERE username = :username");
    query.bindValue(":username", username);
    if (query.exec() && query.next()) {
        int count = query.value(0).toInt();
        closeDatabase();
        return count > 0;
    }

    qWarning() << "Failed to check if user exists:" << query.lastError().text();
    closeDatabase();
    return false;
}
