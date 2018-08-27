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

#include <vector>
#include <sstream>
#include "OpenPgpSign.h"

OpenPgpSign::OpenPgpSign(gpgme_sig_mode_t _sigMode, Properties *_properties, const string *emailAddr) {
    sigMode     = _sigMode;
    email       = emailAddr;
    properties  = _properties;
    key         = nullptr;
    signature   = nullptr;
    gpgme_check_version (nullptr);
    setlocale(LC_ALL, "");
    gpgme_set_locale(nullptr, LC_CTYPE, setlocale(LC_CTYPE, nullptr));
#ifndef WIN32
    gpgme_set_locale(nullptr, LC_MESSAGES, setlocale(LC_MESSAGES, nullptr));
#endif
    if ((err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP))) {
        throw PgpSignException(__FILE__, __LINE__, err);
    }

    // Create the GPGME Context
    if ((err = gpgme_new(&ctx))) {
        throw PgpSignException(__FILE__, __LINE__, err);
    }

    // Set the context to textmode
    gpgme_set_textmode(ctx, 1);
    // Enable ASCII armor on the context
    gpgme_set_armor(ctx, 1);

    keyServer = properties->get("keyServer", new string("pgp.mit.edu"), false);
}

OpenPgpSign::OpenPgpSign(gpgme_sig_mode_t _sigMode, Properties *properties) : OpenPgpSign(_sigMode, properties, nullptr) {}

OpenPgpSign::~OpenPgpSign() {
    if (in) {
        gpgme_data_release(in);
        in = nullptr;
    }
    if (out) {
        gpgme_data_release(out);
        out = nullptr;
    }
    if (key) {
        gpgme_key_release(key);
    }
    if (ctx) {
        gpgme_release(ctx);
        ctx = nullptr;
    }
    delete email;
    delete keyId;
    delete keyName;
    delete keyEmail;
    delete signature;
}

string OpenPgpSign::sign(const string fileToBeSigned) {
    // Create a data object pointing to the input file
    if ((err = gpgme_data_new_from_file(&in, fileToBeSigned.c_str(), 1))) {
        throw PgpSignException(__FILE__, __LINE__, err);
    }

    // Create a data object pointing to the out buffer
    if ((err = gpgme_data_new(&out))) {
        throw PgpSignException(__FILE__, __LINE__, err);
    }
    selectBestSigningKey();

    // Sign the contents of "in" using the defined mode and place it into "out"
    if ((err = gpgme_op_sign(ctx, in, out, sigMode))) {
        throw PgpSignException(__FILE__, __LINE__, err);
    }
    gpgme_data_release(in);
    in = nullptr;

    // Rewind the "out" data object
    if (gpgme_data_seek(out, 0, SEEK_SET)) {
        throw PgpSignException(__FILE__, __LINE__, gpgme_err_code_from_errno(errno));
    }
    // Read the contents of "out" and place it into buf

    // todo something like this method may work instead the vector

    size_t size/*  = (int) sig.size()*/;
    char *sig = gpgme_data_release_and_get_mem(out, &size);
    out = nullptr;

    if (!sig) {
        throw PgpSignException(__FILE__, __LINE__, gpgme_err_code_from_errno(errno));
    }

    char *arr = new char[size + 1];
    copy(sig, &(sig[size]), arr);
    arr[size] = 0;
    signature = new string(arr);
    delete[] sig;
    delete[] arr;

//  todo check if this->key is uploaded on the default key server and upload it, if not (maybe store the key ID as uploaded in the properties?).
//    if (*keyId!=*properties->get("keyId")) {
//        properties->put("keyId", *keyId);
//    }
    return *signature;
}

void OpenPgpSign::selectBestSigningKey() {
    gpgme_key_t signingKey = nullptr;
    err = gpgme_op_keylist_start(ctx, nullptr, 1);

    const char *szEmail = email ? email->c_str() : nullptr;
    if (!email) {
        cout << "No email address found in properties to select the right key for signature." << endl;
    }

    unsigned int mostKeySignatures = 0;
    gpgme_key_t mostSignedKey = nullptr;
    while (!err) {
        gpgme_key_t pKey;
        err = gpgme_op_keylist_next(ctx, &pKey);
        if (!err) {
            if (canSign(pKey)) {
                char *_keyEmail = (pKey->uids && pKey->uids->email) ? pKey->uids->email : nullptr;
                if (szEmail && _keyEmail && !strcasecmp(szEmail, _keyEmail) && !pKey->invalid) {
                    if (signingKey) {
                        gpgme_key_release(signingKey);
                    }
                    signingKey = pKey;
                    if (mostSignedKey) {
                        gpgme_key_release(mostSignedKey);
                    }
                } else {
                    if (!signingKey) {
                        //get best key (first criterion = most public signatures, second criterion: best info)
                        // count signatures
                        unsigned int nKeySigs = countSignatures(pKey);
                        if (nKeySigs >= mostKeySignatures) {
                            if (nKeySigs == mostKeySignatures) {
                                // todo use key with most information
                            } else {
                                mostKeySignatures = nKeySigs;
                                if (mostSignedKey) {
                                    gpgme_key_release(mostSignedKey);
                                }
                                mostSignedKey = pKey;
                            }
                        } else {
                            gpgme_key_release(pKey);
                        }
                    }
                }
            } else {
                // no signing key
                gpgme_key_release(pKey);
            }
        }
    }
    if (gpg_err_code(err) != GPG_ERR_EOF) {
        throw PgpSignException(__FILE__, __LINE__, err);
    } else if (!keyId) {
        cout << "No private key for email address in properties found. Using default key for signature." << endl;
    }
    // try strictly signing should require same email as for Cryptowerk account
    if (!signingKey) {
        signingKey = mostSignedKey;
        cout << "Using default key." << endl;
    } else if (mostSignedKey) {
        gpgme_key_release(mostSignedKey);
    }
    if (signingKey) {
        gpgme_signers_clear(ctx);
        gpgme_signers_add(ctx, signingKey);
        keyId = new string(signingKey->subkeys->keyid);
        gpgme_user_id_t uids = signingKey->uids;
        if (uids) {
            if (uids->name) {
                keyName = new string(uids->name);
            }
            if (uids->email) {
                keyEmail = new string(uids->email);
            }
        }
        key = signingKey;
    } else {
        // todo generate key pair and upload public key
        throw PgpSignException(__FILE__, __LINE__, "GnuPG has no signing key installed.");
    }
}

unsigned int OpenPgpSign::countSignatures(_gpgme_key *const pKey) const {
    unsigned int nKeySigs = 0;
    gpgme_user_id_t uid = pKey->uids;
    while (uid) {
        gpgme_user_id_t nextUid = uid->next;
        gpgme_key_sig_t keysig = uid->signatures;

        while (keysig) {
            gpgme_key_sig_t nextKeySig = keysig->next;
            nKeySigs++;
            keysig = nextKeySig;
        }
        uid = nextUid;
    }
    return nKeySigs;
}

list<map<string, string>> OpenPgpSign::listKeys(const string *optPattern, int isPrivate) {
    auto result = new list<map<string, string>>;
    err = gpgme_op_keylist_start(ctx, optPattern ? optPattern->c_str() : nullptr, isPrivate);
    while (!err) {
        gpgme_key_t key;
        err = gpgme_op_keylist_next(ctx, &key);
        if (!err) {
            if (!key->invalid && key->subkeys->can_sign) {
                auto k = new map<string, string>;
                (*k)["keyId"] = key->subkeys->keyid;
                if (key->uids && key->uids->name)
                    (*k)["name"] = key->uids->name;
                if (key->uids && key->uids->email)
                    (*k)["email"] = key->uids->email;
                result->push_back(*k);
            }
            gpgme_key_release(key);
        }
    }
    if (gpg_err_code(err) != GPG_ERR_EOF) {
        fprintf(stderr, "can not list keys: %s\n", gpgme_strerror(err));
        exit(1);
    }
    return *result;
}

// listing installed public keys
list<map<string, string>> OpenPgpSign::listPublicKeys(const string *optPattern) {
    return listKeys(optPattern, 0);
}

// listing installed private keys
// implement listing, installed public keys
list<map<string, string>> OpenPgpSign::listPrivateKeys(const string *optPattern) {
    return listKeys(optPattern, 1);
}

bool OpenPgpSign::canSign(gpgme_key_t key) {
    // bad practice to use main key for signing
    bool canSign = static_cast<bool>(key->can_sign);
    gpgme_subkey_t subKey = key->subkeys;
    while (!canSign && subKey) {
        canSign = static_cast<bool>(subKey->can_sign);
        subKey = subKey->next;
    }
    return canSign;
}

JSON OpenPgpSign::toJson() const {
    JSON json;
    if (keyId) {
        json["keyId"] = *keyId;
    }
    if (keyServer) {
        json["keyServer"] = *keyServer;
    }
    if (signature) {
        size_t start = strlen(BEGIN_PGP_SIGNATURE);
        size_t end = strlen(END_PGP_SIGNATURE);
        unsigned long size = signature->size();
        string sig = signature->substr(start, size - start - end);
        replace(sig.begin(), sig.end(), '\n', ' ');
        json["signature"] = sig;
    }
    return json;
}

//todo implement searching, downloading, verifying, installing, trusting public key by key ID


//todo implement generating key pair and uploading public key

// verify signature
JSON OpenPgpSign::verify(const string fileToBeVerified, string *_signature) {
    auto *sig = _signature ? _signature : signature;
    if (!sig) {
        throw PgpSignException(__FILE__, __LINE__, "No signature set.");
    }
    // Create a data object pointing to the input file
    if ((err = gpgme_data_new_from_file(&in, fileToBeVerified.c_str(), 1))) {
        throw PgpSignException(__FILE__, __LINE__, err);
    }
    expandSigIfNeccesary(sig);
    gpgme_data_t s;
    if ((err = gpgme_data_new_from_mem(&s, sig->c_str(), sig->size(), 0))) {
        throw PgpSignException(__FILE__, __LINE__, err);
    }

    if ((err = gpgme_op_verify(ctx, s, in, nullptr))) {
        throw PgpSignException(__FILE__, __LINE__, err);
    }
    gpgme_data_release(s);
    gpgme_data_release(in);
    in = nullptr;
    gpgme_verify_result_t verResult = gpgme_op_verify_result(ctx);
    if (!(verResult->signatures->summary & GPGME_SIGSUM_VALID)) {
        throw PgpSignException(__FILE__, __LINE__, "invalid signature.");
    }
    JSON json;
    json["isValid"] = (verResult->signatures->summary & GPGME_SIGSUM_VALID) != 0;
    json["isDeVS"] = verResult->signatures->is_de_vs != 0;
    json["fingerprint"] = verResult->signatures->fpr;
    json["timestamp"] = verResult->signatures->timestamp;
    // tod get key from fpr and add email and other key information

    return json;
}

void OpenPgpSign::expandSigIfNeccesary(string *sig) const {
    if (sig->find(BEGIN_PGP_SIGNATURE) == string::npos) {
        replace(sig->begin(), sig->end(), ' ', '\n');
        sig->insert((size_t)0, BEGIN_PGP_SIGNATURE);
        sig->append(END_PGP_SIGNATURE);
    }
}
