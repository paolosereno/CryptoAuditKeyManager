#include "forensicerrorhandler.h"
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QDir>
#include <QDebug>
#include <QLocale>

ForensicErrorHandler::ForensicErrorHandler(const QString &auditFilePath, const QString &username, QObject *parent)
    : QObject(parent), m_auditFilePath(auditFilePath), m_username(username) {
    // Validazione del percorso del file di audit
    if (!validateAuditFilePath(auditFilePath)) {
        qWarning() << tr("Error: invalid audit file path:") << auditFilePath;
        m_auditFilePath = QDir::homePath() + "/keymanager_audit_fallback.log"; // Fallback
    }

    QFileInfo auditFileInfo(m_auditFilePath);
    QDir dir = auditFileInfo.absoluteDir();
    if (!dir.exists()) {
        if (!dir.mkpath(".")) {
            qWarning() << tr("Error: could not create audit directory:") << dir.absolutePath();
        }
    }

    QFile auditFile(m_auditFilePath);
    if (!auditFile.exists()) {
        if (auditFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&auditFile);
            out << QString("=== %1: %2 ===\n")
                       .arg(tr("Forensic Key Manager Audit Started"))
                       .arg(QLocale().toString(QDateTime::currentDateTime(), QLocale::ShortFormat));
            out << tr("User: %1\n").arg(m_username);
            auditFile.close();
            // Imposta permessi restrittivi (0600)
            auditFile.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
            qDebug() << tr("Audit file created:") << m_auditFilePath;
        } else {
            qWarning() << tr("Error: could not create audit file:") << m_auditFilePath << ":" << auditFile.errorString();
        }
    }
}

void ForensicErrorHandler::handleError(const QWidget *parent, const QString &context, const QString &message, Severity severity, bool showDialog) {
    QString fullMessage = QString("%1: %2").arg(context, message);
    logToAuditTrail(context, fullMessage);

    if (showDialog) {
        QMessageBox::Icon icon;
        QString dialogTitle;
        switch (severity) {
        case Severity::Info:
            dialogTitle = tr("Information");
            icon = QMessageBox::Information;
            break;
        case Severity::Warning:
            dialogTitle = tr("Warning");
            icon = QMessageBox::Warning;
            break;
        case Severity::Critical:
            dialogTitle = tr("Critical Error");
            icon = QMessageBox::Critical;
            break;
        }

        QMessageBox msgBox(icon, dialogTitle, fullMessage, QMessageBox::Ok, const_cast<QWidget*>(parent));
        msgBox.setTextFormat(Qt::PlainText);
        msgBox.exec();
    }

    switch (severity) {
    case Severity::Info:
        qInfo() << fullMessage;
        break;
    case Severity::Warning:
        qWarning() << fullMessage;
        break;
    case Severity::Critical:
        qCritical() << fullMessage;
        break;
    }
}

void ForensicErrorHandler::logToAuditTrail(const QString &action, const QString &details) {
    QFile auditFile(m_auditFilePath);
    if (!auditFile.open(QIODevice::Append | QIODevice::Text)) {
        qWarning() << tr("Error: could not open audit file for writing:") << m_auditFilePath << ":" << auditFile.errorString();
        return;
    }

    QTextStream out(&auditFile);
    QString timestamp = QLocale().toString(QDateTime::currentDateTime(), QLocale::LongFormat);
    out << QString("[%1] User: %2 | Action: %3 | Details: %4\n")
               .arg(timestamp, m_username, action, details);
    auditFile.close();
    // Imposta permessi restrittivi dopo ogni scrittura
    auditFile.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
    qDebug() << tr("Audit written: [%1] %2: %3").arg(timestamp, action, details);
}

QString ForensicErrorHandler::severityToString(Severity severity) const {
    switch (severity) {
    case Severity::Info: return tr("INFO");
    case Severity::Warning: return tr("WARNING");
    case Severity::Critical: return tr("CRITICAL");
    }
    return tr("UNKNOWN");
}

bool ForensicErrorHandler::validateAuditFilePath(const QString &path) const {
    if (path.isEmpty()) return false;
    QFileInfo fileInfo(path);
    // Controlla se il file o la directory genitore è scrivibile
    return fileInfo.exists() ? fileInfo.isWritable() : fileInfo.dir().isReadable();
}
