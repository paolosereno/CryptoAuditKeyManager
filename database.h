#ifndef DATABASE_H
#define DATABASE_H

#include <QObject>
#include <QString>
#include <QSqlDatabase>
#include <argon2.h>
#include <openssl/rand.h>

class Database : public QObject {
    Q_OBJECT
public:
    explicit Database(const QString &dbPath, QObject *parent = nullptr);
    ~Database();

    bool initialize();
    bool authenticateUser(const QString &username, const QString &password);
    bool registerUser(const QString &username, const QString &password);
    bool isAccountLocked(const QString &username);
    void logLoginAttempt(const QString &username, bool success);
    bool hasUsers();
    bool removeUser(const QString &username);
    bool userExists(const QString &username); // New function to check if a user exists

private:
    QString m_dbPath;
    QSqlDatabase m_db;

    bool createTables();
    bool openDatabase();
    void closeDatabase();
};

#endif // DATABASE_H
