#ifndef DATABASE_H
#define DATABASE_H

#include <QObject>
#include <QString>
#include <QSqlDatabase>
#include <argon2.h>
#include <openssl/rand.h>
#include "forensicerrorhandler.h"
#include "securityutils.h"

class Database : public QObject {
    Q_OBJECT
public:
    explicit Database(const QString &dbPath, ForensicErrorHandler *errorHandler, QObject *parent = nullptr);
    ~Database();

    bool initialize();
    bool authenticateUser(const QString &username, const QString &password);
    bool registerUser(const QString &username, const QString &password);
    bool isAccountLocked(const QString &username);
    void logLoginAttempt(const QString &username, bool success);
    bool hasUsers();
    bool removeUser(const QString &username);
    bool userExists(const QString &username);
    void cleanupLoginAttempts();

private:
    bool createTables();
    bool openDatabase();
    void closeDatabase();
    bool isValidUsername(const QString &username) const;
    QString m_dbPath;
    QSqlDatabase m_db;
    ForensicErrorHandler *m_errorHandler;
    QString m_connectionName;
};

#endif // DATABASE_H
