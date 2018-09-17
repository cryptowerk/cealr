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

/*!
@brief Exception for GPG errors

This exception indicates errors returned from GPG or other fatal states during signing/verifying
*/
class pgp_exception : public exception
{
private:
  runtime_error _what;

public:
  /*!
  Constructor with code pointer (file and line) and gpg error code

  @param file File name __FILE__
  @param line Line number __LINE__
  @param err GPG error code
  */
  pgp_exception(const string &file, const int line, const gpgme_error_t err) : _what(
      ("" + file + ":" + to_string(line) + ": " + gpgme_strsource(err) + ": " + gpgme_strerror(err)).c_str()) {}

  /*!
  Constructor with code pointer (file and line) and error message

  @param file File name __FILE__
  @param line Line number __LINE__
  @param error message
  */
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
  const string *email;  //!< signing users email is used to find signing key/evaluate signatures

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

  /*!
  @brief Verifying if a signature is valid for a file
  this method is verifying if the signature in param _signature matches the file in param file_to_be_verified.

  @param file_to_be_verified file to verify the signature with
  @param _signature to be verified

  @return gpgme_verify_result_t structure from gpgme
  */
  gpgme_verify_result_t verify_file_signature(const string &file_to_be_verified, string *_signature);

  /*!
  @brief list keys that are matching a pattern in local gpg keyring

  This method returns a list with maps that contain the following values either for all keys that are available in the
  local gpg key ring (if parameter opt_pattern is NULL) or for all those keys that are matching the pattern given in
  opt_pattern. The map entries contain for each matching key the values "keyId", "name", "email", and "keyTrustLevel",
  if these values set for the key.

  @param opt_pattern contains either pattern for keys to be returned (e.g. email, fingerprint or keyId) or NULL for all keys
  @param is_private if true the maps contain only entries when the private key is available in the local keyring
  @return List with maps containing the values for "keyId", "name", "email", and "keyTrustLevel",
  of each matching key, if these values set for the key.
  */
  list<map<string, string>> list_keys(const string *opt_pattern, int is_private);

//  gpgme_key_t *list_keys_for_import(const string &fpr, int is_private);

public:
  /*!
  @brief constructor with sig mode and properties

  @param _sig_mode: GPGME_SIG_MODE_NORMAL for embedded signatures in common PGO formaat,
                    GPGME_SIG_MODE_DETACH for detached signature,
                    GPGME_SIG_MODE_CLEAR for signatures in clear text

  @param _properties property file
  */
  open_pgp(gpgme_sig_mode_t _sig_mode, class properties *_properties);

  /*!
  @brief constructor with sig mode, properties and email address of the signer

  @param _sig_mode: GPGME_SIG_MODE_NORMAL for embedded signatures in common PGO formaat,
                    GPGME_SIG_MODE_DETACH for detached signature,
                    GPGME_SIG_MODE_CLEAR for signatures in clear text

  @param _properties property file
  @param email_addr contains the verified email address the signer is registered with at cryptowerk
  */
  open_pgp(gpgme_sig_mode_t _sig_mode, class properties *_properties, const string *email_addr);

  virtual ~open_pgp();

  /*!
  @brief signing file with best matching local private key and exporting public part of signing key
  This method is trying to find the best key for the signature and signs the file referenced by
  parameter file_to_be_signed with this key. Additionally it tries to export the signing key to a key server.

  @param file_to_be_signed File to be signed

  @return the signature of the file
  */
  string sign(string file_to_be_signed);

  /*!
  @brief verifying signature

  This method tries to find signing key from the signature in the local keyring. If it  cannot be found there it is
  tried to be imported from a public key server. If the key was found the signature will be verified and the result of
  the verification is returned along with the data from the signing key.

  @param file_to_be_verified
  @param _signature contains the signature to be verified.

  @return map with detailled verification results and some some data from the signing key.
  */
  json verify(const string &file_to_be_verified, string *_signature = nullptr);

  /*!
  @brief list public keys that are matching a pattern in local gpg keyring

  This method returns a list with maps that contain the following values either for all public keys that are available
  in the local gpg key ring (if parameter opt_pattern is NULL) or for all those keys that are matching the pattern
  given in the parameter opt_pattern. The map entries contain for each matching public key the values "keyId",
  "name", "email", and "keyTrustLevel", if these values set for the key.

  @return List with maps containing the values for "keyId", "name", "email", and "keyTrustLevel",
  of each matching public key in the local gpg keyring, if these values set for the key.
  */
  list<map<string, string>> list_public_keys(const string *opt_pattern);

  /*!
  @brief list private keys that are matching a pattern in local gpg keyring

  This method returns a list with maps that contain the following values either for all private keys that are available
  in the local gpg key ring (if parameter opt_pattern is NULL) or for all those keys that are matching the pattern
  given in the parameter opt_pattern. The map entries contain for each matching private key the values "keyId", "name",
  "email", and "keyTrustLevel", if these values set for the key.

  @return List with maps containing the values for "keyId", "name", "email", and "keyTrustLevel",
  of each matching private key in the local gpg keyring, if these values set for the key.
  */
  list<map<string, string>> list_private_keys(const string *opt_pattern);

  /*!
  @brief Find best possible key for signing
  This method tries to find the best possible key for signing a file for cryptowerks sealing purposes in the local
  GPG keyring and stores this key into membervariable key of the open_pgp object.

  It prioritizes keys that have the same email address that was used to register the account with cryptowerk because
  it will be verified by cryptowerk.
  */
  void select_best_signing_key();

  /*!
  @brief Detects for a given key if it is able to sign a file.

  @param _key points to the key to be checked.

  @return true, if the key can be used to sign a file, otherwise false
  */
  bool can_sign(gpgme_key_t _key);

  /*!
  @brief Counts signatures for a given key

  @param _key points to the key to be checked

  @return number of signatures from other private keys
  */
  unsigned int count_signatures(gpgme_key_t _key) const;

  /*!
  @brief Get JSON for cealr
  Returns signature and relevant metadate for sealing a file with cryptowerk as JSON.
  @return  signature and relevant metadate for sealing a file with cryptowerk as JSON.
  */
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
