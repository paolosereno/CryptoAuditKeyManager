// --- File: keymanagerwindow.h ---
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
    void logoutRequested(); // Signal for logout

private slots:
    void generateAndSaveKey();
    void verifyKey();
    void showAuditLog();
    void handleLogout();
    void copyPublicKeyToClipboard(); // New: Slot for copying public key

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    ForensicErrorHandler *errorHandler;
    QString m_username;
    QLineEdit *passwordEdit;
    QLineEdit *commentEdit;
    QComboBox *keyLengthCombo;
    QComboBox *keyFormatCombo;
    QPushButton *generateButton;
    QPushButton *verifyButton;
    QPushButton *showLogButton;
    QPushButton *logoutButton;
    QPushButton *copyPublicKeyButton; // New: Button for copying public key
    QString m_lastPublicKeyPath;

    void setupUi();
    bool validatePassword(const QString &password) const;
    bool validateKeyLength(int keyLength) const;
    bool validateComment(const QString &comment) const;
};

#endif // KEYMANAGERWINDOW_H
