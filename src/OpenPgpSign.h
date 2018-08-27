/*
 * _____ _____  _____  ___    ______
 *|   __|   __|/  _  \|   |  |   _  |  Command line tool for sealing files with Cryptowerk API
 *|  |__|   __|   _   |   |__|
 *|_____|_____|__| |__|______|__|\__\  https://github.com/cryptowerk/cealr
 *
 *Licensed under the Apache 2.0 License <https://opensource.org/licenses/Apache-2.0>.
 *Copyright (c) 2018 Cryptowerk <http://www.cryptowerk.com>.
 *
 */

#ifndef CEALR_OPENPGPSIGN_H
#define CEALR_OPENPGPSIGN_H

#include <cstdlib>
#include <cerrno>
#include <clocale>
#include <iostream>
#include <list>
#include <map>
#include "Properties.h"

#include <gpgme.h>
#include <nlohmann/json.hpp>

using JSON = nlohmann::json;

using namespace std;

#define BUF_SIZE 512
#define BEGIN_PGP_SIGNATURE "-----BEGIN PGP SIGNATURE-----\n"
#define END_PGP_SIGNATURE   "-----END PGP SIGNATURE-----\n"

class PgpSignException: public exception {
private:
    runtime_error _what;

public:
    PgpSignException(const string &file, const int line, const gpgme_error_t err) : _what(("" + file + ":" + to_string(line) + ": " + gpgme_strsource(err) + ": " + gpgme_strerror(err)).c_str()) {}
    PgpSignException(const string &file, const int line, const string &errStr) : _what(("" + file + ":" + to_string(line) + ": " + errStr ).c_str()) {}
    const char *what() {
        return _what.what();
    }
};

class OpenPgpSign {
private:
    const string *email;
    Properties *properties;
    string *keyId;
    string *keyName;
    string *keyEmail;
    string *signature;
    string *keyServer;

    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_data_t in, out;
    gpgme_sig_mode_t sigMode;
    gpgme_key_t key;

    list<map<string, string>> listKeys(const string *optPattern, int isPrivate);

public:
    OpenPgpSign(gpgme_sig_mode_t _sigMode, Properties *_properties);
    OpenPgpSign(gpgme_sig_mode_t _sigMode, Properties *_properties, const string *emailAddr);

    virtual ~OpenPgpSign();
    string sign(string fileToBeSigned);
    JSON verify(string fileToBeVerified, string *_signature = nullptr);
    list<map<string, string>> listPublicKeys(const string *optPattern);
    list<map<string, string>> listPrivateKeys(const string *optPattern);

    void selectBestSigningKey();

    bool canSign(gpgme_key_t pKey);

    unsigned int countSignatures(_gpgme_key*pKey) const;

    JSON toJson() const;

    void expandSigIfNeccesary(string *sig) const;
};

#endif //CEALR_OPENPGPSIGN_H
