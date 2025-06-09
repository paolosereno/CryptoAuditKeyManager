#include "securityutils.h"
#include <QRegularExpression>


namespace SecurityUtils {
bool validatePassword(const QString &password, ForensicErrorHandler *errorHandler) {
    QRegularExpression regex("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[!@#$%^&*_])[A-Za-z\\d!@#$%^&*_]{12,}$");
    bool isValid = regex.match(password).hasMatch();
    if (!isValid && errorHandler) {
        errorHandler->handleError(nullptr, QObject::tr("Password Validation"),
                                  QObject::tr("Password must be at least 12 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character (!@#$%^&*_)."),
                                  ForensicErrorHandler::Severity::Warning);
    }
    return isValid;
}
}
