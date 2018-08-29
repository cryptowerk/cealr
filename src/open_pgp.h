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

using json = nlohmann::json;

using namespace std;

#define BUF_SIZE 512
#define BEGIN_PGP_SIGNATURE "-----BEGIN PGP SIGNATURE-----\n"
#define END_PGP_SIGNATURE   "-----END PGP SIGNATURE-----\n"

class pgp_exception : public exception
{
private:
  runtime_error _what;

public:
  pgp_exception(const string &file, const int line, const gpgme_error_t err) : _what(
      ("" + file + ":" + to_string(line) + ": " + gpgme_strsource(err) + ": " + gpgme_strerror(err)).c_str()) {}

  pgp_exception(const string &file, const int line, const string &errStr) : _what(
      ("" + file + ":" + to_string(line) + ": " + errStr).c_str()) {}

  const char *what()
  {
    return _what.what();
  }
};

class open_pgp
{
private:
  const string *email;

  class Properties *properties;

  string *key_id;
  string *key_name;
  string *key_email;
  string *signature;
  string *key_server;

  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in, out;
  gpgme_sig_mode_t sig_mode;
  gpgme_key_t key;

  list<map<string, string>> list_keys(const string *opt_pattern, int is_private);

public:
  open_pgp(gpgme_sig_mode_t _sig_mode, class Properties *_properties);

  open_pgp(gpgme_sig_mode_t _sig_mode, class Properties *_properties, const string *email_addr);

  virtual ~open_pgp();

  string sign(string file_to_be_signed);

  json verify(string file_to_be_verified, string *_signature = nullptr);

  list<map<string, string>> list_public_keys(const string *opt_pattern);

  list<map<string, string>> list_private_keys(const string *opt_pattern);

  void select_best_signing_key();

  bool canSign(gpgme_key_t pKey);

  unsigned int count_signatures(_gpgme_key *const _key) const;

  json toJson() const;

  void expand_sig_if_neccesary(string *sig) const;
};

#endif //CEALR_OPENPGPSIGN_H
