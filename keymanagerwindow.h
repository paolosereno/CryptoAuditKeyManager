#ifndef KEYMANAGERWINDOW_H
#define KEYMANAGERWINDOW_H

#include <QMainWindow>
#include <openssl/evp.h>
#include "forensicerrorhandler.h"
#include <memory>

class QLineEdit;
class QPushButton;
class QComboBox;

class KeyManagerWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit KeyManagerWindow(const QString &auditFilePath, const QString &username, QWidget *parent = nullptr);
    ~KeyManagerWindow();

signals:
    void logoutRequested();

private slots:
    void generateAndSaveKey();
    void verifyKey();
    void showAuditLog();
    void handleLogout();
    void copyPublicKeyToClipboard();
    void changeLanguage(const QString &locale);

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    ForensicErrorHandler *errorHandler;
    QString m_username;
    QLineEdit *passwordEdit;
    QLineEdit *commentEdit;
    QComboBox *keyLengthCombo;
    QComboBox *keyFormatCombo;
    QComboBox *languageCombo;
    QComboBox *keyTypeCombo;
    QPushButton *generateButton;
    QPushButton *verifyButton;
    QPushButton *showLogButton;
    QPushButton *logoutButton;
    QPushButton *copyPublicKeyButton;
    QString m_lastPublicKeyPath;

    void setupUi();
    bool validatePassword(const QString &password) const;
    bool validateKeyLength(int keyLength, const QString &keyType) const;
    bool validateComment(const QString &comment) const;
    bool validateKeyType(const QString &keyType) const;
    bool isKeyTypeSupportedForFormat(const QString &keyType, const QString &format) const; // Nuova funzione per validazione formato
};

#endif // KEYMANAGERWINDOW_H
