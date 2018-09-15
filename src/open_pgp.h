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

//#include <cstdlib>
//#include <cerrno>
//#include <clocale>
#include <list>
#include <map>
#include "properties.h"
#include "file_util.h"

#include <gpgme.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

using namespace std;

#define BEGIN_PGP_SIGNATURE "-----BEGIN PGP SIGNATURE-----\n"
#define END_PGP_SIGNATURE   "-----END PGP SIGNATURE-----\n"

static const char *const OPENPGP_DEFAULT_KEYSERVER = "hkp://pgp.mit.edu";

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

  class properties *p_properties;

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

  gpgme_verify_result_t verify_file_signature(const string &file_to_be_verified, string *_signature);

  list<map<string, string>> list_keys(const string *opt_pattern, int is_private);

//  gpgme_key_t *list_keys_for_import(const string &fpr, int is_private);

public:
  open_pgp(gpgme_sig_mode_t _sig_mode, class properties *_properties);

  open_pgp(gpgme_sig_mode_t _sig_mode, class properties *_properties, const string *email_addr);

  virtual ~open_pgp();

  string sign(string file_to_be_signed);

  json verify(const string &file_to_be_verified, string *_signature = nullptr);

  list<map<string, string>> list_public_keys(const string *opt_pattern);

  list<map<string, string>> list_private_keys(const string *opt_pattern);

  void select_best_signing_key();

  bool can_sign(gpgme_key_t _key);

  unsigned int count_signatures(gpgme_key_t _key) const;

  json toJson() const;

  void expand_sig_if_necessary(string *sig) const;

  bool find_and_import_key(const string &fpr);

  string get_trust_level(const gpgme_validity_t &trust) const;

  bool check_trust(gpgme_key_t &_key);

  gpgme_key_t find_key(const string &fpr, gpgme_keylist_mode_t mode = GPGME_KEYLIST_MODE_LOCAL);

  bool export_key(const string &fpr);

  bool is_key_exported(const string &fpr);
};

#endif //CEALR_OPENPGPSIGN_H
