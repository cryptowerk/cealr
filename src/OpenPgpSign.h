/*
 * _____ _____  _____  ____   ______
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

#include <stdlib.h>
#include <errno.h>
#include <locale.h>
#include <iostream>

#include <gpgme.h>

using namespace std;

#define BUF_SIZE 512

class PgpSignException: public exception {
private:
    runtime_error _what;

public:
    PgpSignException(const string &file, const int line, const gpgme_error_t err) : _what(("" + file + ":" + to_string(line) + ": " + gpgme_strsource(err) + ": " + gpgme_strerror(err)).c_str()) {}
    const char *what() {
        return _what.what();
    }
};

class OpenPgpSign {
private:
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_data_t in, out;
    gpgme_sig_mode_t sigMode;

public:
    explicit OpenPgpSign(gpgme_sig_mode_t sigMode);
    virtual ~OpenPgpSign();
    char *sign(string fileToBeSigned);
};

#endif //CEALR_OPENPGPSIGN_H
