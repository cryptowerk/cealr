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

#include <vector>
#include <sstream>
#include "OpenPgpSign.h"

OpenPgpSign::OpenPgpSign(gpgme_sig_mode_t _sigMode) {
    sigMode = _sigMode;

    gpgme_check_version (nullptr);
    setlocale(LC_ALL, "");
    gpgme_set_locale(nullptr, LC_CTYPE, setlocale(LC_CTYPE, nullptr));
#ifndef WIN32
    gpgme_set_locale(nullptr, LC_MESSAGES, setlocale(LC_MESSAGES, nullptr));
#endif

    // Create the GPGME Context
    if ((err = gpgme_new(&ctx))) {
        throw PgpSignException(__FILE__, __LINE__, err);
    }

    // Set the context to textmode
    gpgme_set_textmode(ctx, 1);
    // Enable ASCII armor on the context
    gpgme_set_armor(ctx, 1);
    // end constructor
}

OpenPgpSign::~OpenPgpSign() {
    if (in) {
        gpgme_data_release(in);
        in = nullptr;
    }

    if (out) {
        gpgme_data_release(out);
        out = nullptr;
    }

    if (ctx){
        gpgme_release(ctx);
        ctx = nullptr;
    }
}

char *OpenPgpSign::sign(const string fileToBeSigned) {
    // Create a data object pointing to the input file
    if ((err = gpgme_data_new_from_file(&in, fileToBeSigned.c_str(), 1))) {
        throw PgpSignException(__FILE__, __LINE__, err);
    }

    // Create a data object pointing to the out buffer
    if ((err = gpgme_data_new(&out))) {
        throw PgpSignException(__FILE__, __LINE__, err);
    }

    // Sign the contents of "in" using the defined mode and place it into "out"
    if ((err = gpgme_op_sign(ctx, in, out, sigMode))) {
        throw PgpSignException(__FILE__, __LINE__, err);
    }

    gpgme_data_release(in);
    in = nullptr;

    vector<char> signature;
    char buf[BUF_SIZE + 1];

    // Rewind the "out" data object
    if (gpgme_data_seek(out, 0, SEEK_SET)) {
        throw PgpSignException(__FILE__, __LINE__, gpgme_err_code_from_errno(errno));
    }

    // Read the contents of "out" and place it into buf
    ssize_t readSize;
    while ((readSize = gpgme_data_read(out, buf, BUF_SIZE)) > 0) {
        signature.insert(signature.end(), buf, buf+readSize);
    }

    gpgme_data_release(out);
    out = nullptr;

    if (readSize < 0) {
        throw PgpSignException(__FILE__, __LINE__, gpgme_err_code_from_errno(errno));
    }

    char *arr = new char[signature.size()];
    copy(signature.begin(), signature.end(), arr);
    return arr;
}

