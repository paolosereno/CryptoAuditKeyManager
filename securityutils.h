#ifndef SECURITYUTILS_H
#define SECURITYUTILS_H

#include <QString>
#include "forensicerrorhandler.h"

namespace SecurityUtils {
/**
     * @brief Valida una password secondo i requisiti di sicurezza.
     * @param password La password da validare.
     * @param errorHandler Puntatore al gestore degli errori per il logging.
     * @return true se la password è valida, false altrimenti.
     */
bool validatePassword(const QString &password, ForensicErrorHandler *errorHandler);
}

#endif // SECURITYUTILS_H
