#ifndef FORENSICERRORHANDLER_H
#define FORENSICERRORHANDLER_H

#include <QObject>
#include <QString>
#include <QMessageBox>

class ForensicErrorHandler : public QObject {
    Q_OBJECT
public:
    enum class Severity { Info, Warning, Critical };

    explicit ForensicErrorHandler(const QString &auditFilePath, const QString &username, QObject *parent = nullptr);
    void handleError(QWidget *parent, const QString &context, const QString &message, Severity severity = Severity::Warning, bool showDialog = true);
    QString getAuditFilePath() const { return m_auditFilePath; }
    void logToAuditTrail(const QString &action, const QString &details);

private:
    QString m_auditFilePath;
    QString m_username;

    QString severityToString(Severity severity) const;
    bool validateAuditFilePath(const QString &path) const;
};

#endif // FORENSICERRORHANDLER_H
