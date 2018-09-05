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

//#include <vector>
//#include <sstream>
#include "open_pgp.h"

open_pgp::open_pgp(gpgme_sig_mode_t _sig_mode, Properties *_properties, const string *email_addr)
{
  sig_mode = _sig_mode;
  email = email_addr;
  properties = _properties;
  key = nullptr;
  signature = nullptr;
  in = nullptr;
  out = nullptr;
  key_id = nullptr;
  key_name = nullptr;
  key_email = nullptr;
  gpgme_check_version (nullptr);
  setlocale(LC_ALL, "");
  gpgme_set_locale(nullptr, LC_CTYPE, setlocale(LC_CTYPE, nullptr));
#ifndef WIN32
  gpgme_set_locale(nullptr, LC_MESSAGES, setlocale(LC_MESSAGES, nullptr));
#endif
  if ((err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP)))
  {
    throw pgp_exception(__FILE__, __LINE__, err);
  }

  // Create the GPGME Context
  if ((err = gpgme_new(&ctx)))
  {
    throw pgp_exception(__FILE__, __LINE__, err);
  }
  gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
//  gpgme_engine_info_t info = gpgme_ctx_get_engine_info(ctx);

  // Set the context to textmode
  gpgme_set_textmode(ctx, 1);
  // Enable ASCII armor on the context
  gpgme_set_armor(ctx, 1);

  key_server = properties->get("keyServer", new string(OPENPGP_DEFAULT_KEYSERVER), false);
  if (key_server->find("://") == string::npos)
  {
    string *old = key_server;
    *key_server = "hkp://" + *key_server;
    delete old;
  }
}

open_pgp::open_pgp(gpgme_sig_mode_t _sig_mode, Properties *properties) : open_pgp(_sig_mode, properties, nullptr) {}

open_pgp::~open_pgp()
{
  if (in)
  {
    gpgme_data_release(in);
    in = nullptr;
  }
  if (out)
  {
    gpgme_data_release(out);
    out = nullptr;
  }
  if (key)
  {
    gpgme_key_release(key);
  }
  if (ctx)
  {
    gpgme_release(ctx);
    ctx = nullptr;
  }
  delete key_id;
  delete key_name;
  delete key_email;
  delete signature;
  delete key_server;
}

string open_pgp::sign(const string file_to_be_signed)
{
  // Create a data object pointing to the input file
  if ((err = gpgme_data_new_from_file(&in, file_to_be_signed.c_str(), 1)))
  {
    throw pgp_exception(__FILE__, __LINE__, err);
  }

  // Create a data object pointing to the out buffer
  if ((err = gpgme_data_new(&out)))
  {
    throw pgp_exception(__FILE__, __LINE__, err);
  }
  select_best_signing_key();
  if (!key){
    cerr << "There is no private key to sign with installed with your GPG right now." << endl
         << "Please use gpg to import or generate a private key for you. " << endl
         << "Ideally it should have the same email address as your CryptoWerk account" << endl
         << "and it should have as many key signers as possible in order to establish" << endl
         << "trust among the people who want to verify your signatures." << endl;
  }

  // Sign the contents of "in" using the defined mode and place it into "out"
  if ((err = gpgme_op_sign(ctx, in, out, sig_mode)))
  {
    throw pgp_exception(__FILE__, __LINE__, err);
  }
  gpgme_data_release(in);
  in = nullptr;

  // Rewind the "out" data object
  if (gpgme_data_seek(out, 0, SEEK_SET))
  {
    throw pgp_exception(__FILE__, __LINE__, gpgme_err_code_from_errno(errno));
  }
  // Read contents from "out", place into sig and release out
  size_t size;
  char *sig = gpgme_data_release_and_get_mem(out, &size);
  out = nullptr;

  if (!sig)
  {
    throw pgp_exception(__FILE__, __LINE__, gpgme_err_code_from_errno(errno));
  }

  char *arr = new char[size + 1];
  copy(sig, &(sig[size]), arr);
  arr[size] = 0;
  signature = new string(arr);
  delete[] sig;
  delete[] arr;

  // check if this->key is uploaded on the default key server and upload it, if not (maybe store the key ID as uploaded in the properties?).
  export_key(key->fpr);

  return *signature;
}

void open_pgp::select_best_signing_key()
{
  gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_LOCAL);
  gpgme_key_t signing_key = nullptr;
  err = gpgme_op_keylist_start(ctx, nullptr, 1);

  const char *_email = email ? email->c_str() : nullptr;
  if (!email)
  {
    cout << "No email address found in properties to select the right key for signature." << endl;
  }

  unsigned int most_key_signatures = 0;
  gpgme_key_t most_signed_key = nullptr;
  while (!err)
  {
    gpgme_key_t _key;
    err = gpgme_op_keylist_next(ctx, &_key);
    if (!err)
    {
      if (can_sign(_key))
      {
        char *_key_email = (_key->uids && _key->uids->email) ? _key->uids->email : nullptr;
        if (_email && _key_email && !strcasecmp(_email, _key_email) && !_key->invalid)
        {
          if (signing_key)
          {
            gpgme_key_release(signing_key);
          }
          signing_key = _key;
          if (most_signed_key)
          {
            gpgme_key_release(most_signed_key);
          }
        }
        else
        {
          if (!signing_key)
          {
            //get best key (first criterion = most public signatures, second criterion: best info)
            // count signatures
            unsigned int count_key_sigs = count_signatures(_key);
            if (count_key_sigs >= most_key_signatures)
            {
              if (count_key_sigs == most_key_signatures)
              {
                // todo use key with most information?
              }
              else
              {
                most_key_signatures = count_key_sigs;
                if (most_signed_key)
                {
                  gpgme_key_release(most_signed_key);
                }
                most_signed_key = _key;
              }
            }
            else
            {
              gpgme_key_release(_key);
            }
          }
        }
      }
      else
      {
        // no signing key
        gpgme_key_release(_key);
      }
    }
  }
  if (gpg_err_code(err) != GPG_ERR_EOF)
  {
    throw pgp_exception(__FILE__, __LINE__, err);
  }
  else if (!key_id)
  {
    cout << "Private key for email address not fount in properties. Using default key for signature." << endl;
  }
  // try strictly signing should require same email as for Cryptowerk account
  if (!signing_key)
  {
    signing_key = most_signed_key;
    cout << "Using default key." << endl;
  }
  else if (most_signed_key)
  {
    gpgme_key_release(most_signed_key);
  }
  if (signing_key)
  {
    gpgme_signers_clear(ctx);
    gpgme_signers_add(ctx, signing_key);
    key_id = new string(signing_key->subkeys->keyid);
    gpgme_user_id_t uids = signing_key->uids;
    if (uids)
    {
      if (uids->name)
      {
        key_name = new string(uids->name);
      }
      if (uids->email)
      {
        key_email = new string(uids->email);
      }
    }
    key = signing_key;
  }
  else
  {
    // todo generate key pair and upload public key
    list_private_keys(nullptr);
  }
}

unsigned int open_pgp::count_signatures(gpgme_key_t _key) const
{
  unsigned int count_key_sigs = 0;
  gpgme_user_id_t uid = _key->uids;
  while (uid)
  {
    gpgme_user_id_t next_uid = uid->next;
    gpgme_key_sig_t key_sig = uid->signatures;

    while (key_sig)
    {
      gpgme_key_sig_t next_key_sig = key_sig->next;
      count_key_sigs++;
      key_sig = next_key_sig;
    }
    uid = next_uid;
  }
  return count_key_sigs;
}

list<map<string, string>> open_pgp::list_keys(const string *opt_pattern, int is_private)
{
  gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_LOCAL);
  auto result = new list<map<string, string>>;
  err = gpgme_op_keylist_start(ctx, opt_pattern ? opt_pattern->c_str() : nullptr, is_private);
  while (!err)
  {
    gpgme_key_t _key;
    err = gpgme_op_keylist_next(ctx, &_key);
    if (!err)
    {
      if (!_key->invalid /*&& _key->subkeys->can_sign*/)
      {
        auto k = new map<string, string>;
        (*k)["keyId"] = _key->subkeys->keyid;
        if (_key->uids && _key->uids->name)
        {
          (*k)["name"] = _key->uids->name;
        }
        if (_key->uids && _key->uids->email)
        {
          (*k)["email"] = _key->uids->email;
        }
        (*k)["keyTrustLevel"] = get_trust_level(_key->owner_trust);
        result->push_back(*k);
      }
      gpgme_key_release(_key);
    }
  }
  if (gpg_err_code(err) != GPG_ERR_EOF)
  {
    throw pgp_exception(__FILE__, __LINE__, gpgme_strerror(err));
  }
  return *result;
}

string open_pgp::get_trust_level(const gpgme_validity_t &trust) const
{
  string trustLevel;
  switch (trust)
  {
    case GPGME_VALIDITY_UNKNOWN:
      trustLevel = "unknown validity";
      break;
    case GPGME_VALIDITY_UNDEFINED:
      trustLevel = "unknown user";
      break;
    case GPGME_VALIDITY_NEVER:
      trustLevel = "known validity: DO NOT TRUST";
      break;
    case GPGME_VALIDITY_MARGINAL:
      trustLevel = "known validity: marginal trust";
      break;
    case GPGME_VALIDITY_FULL:
      trustLevel = "known validity: full trust";
      break;
    case GPGME_VALIDITY_ULTIMATE:
      trustLevel = "known validity: ultimate trust";
      break;
  }
  return trustLevel;
}

// listing installed public keys
list<map<string, string>> open_pgp::list_public_keys(const string *opt_pattern)
{
  return list_keys(opt_pattern, 0);
}

// listing installed private keys
// implement listing, installed public keys
list<map<string, string>> open_pgp::list_private_keys(const string *opt_pattern)
{
  return list_keys(opt_pattern, 1);
}

bool open_pgp::can_sign(gpgme_key_t _key)
{
  // bad practice to use main key for signing
  bool canSign = static_cast<bool>(_key->can_sign);
  gpgme_subkey_t subKey = _key->subkeys;
  while (!canSign && subKey)
  {
    canSign = static_cast<bool>(subKey->can_sign);
    subKey = subKey->next;
  }
  return canSign;
}

json open_pgp::toJson() const
{
  json json;
  if (key_id)
  {
    json["keyId"] = *key_id;
  }
  if (key_server)
  {
    json["keyServer"] = *key_server;
  }
  if (signature)
  {
    size_t start = strlen(BEGIN_PGP_SIGNATURE);
    size_t end = strlen(END_PGP_SIGNATURE);
    unsigned long size = signature->size();
    string sig = signature->substr(start, size - start - end);
    replace(sig.begin(), sig.end(), '\n', ' ');
    json["signature"] = sig;
  }
  return json;
}

//todo implement verifying/trusting public key by key ID


//todo implement importing/generating key pair

// verify signature
json open_pgp::verify(const string &file_to_be_verified, string *_signature)
{
  gpgme_verify_result_t verResult = verify_file_signature(file_to_be_verified, _signature);
  gpgme_sigsum_t sig_sum = verResult->signatures->summary;
  string fpr = verResult->signatures->fpr;
  bool isKeyMissing = (sig_sum & GPGME_SIGSUM_KEY_MISSING) != 0;
  bool isValid = (sig_sum & GPGME_SIGSUM_VALID) != 0;
  bool retry = false;
  if (!isValid)
  {
    if (isKeyMissing)
    {
      retry = find_and_import_key(fpr);
    }
    else if (verResult->signatures->validity == GPGME_VALIDITY_UNKNOWN)
    {
      gpgme_key_t _key = find_key(fpr);
      if (_key)
      {
        // check if key validity is not known
        retry = check_trust(_key);
        if (retry){
          // trust key: sign it; GPGME seems to have no way to manipulate the trust level of a key
//          gpgme_key_release(_key);
//          _key = find_key(fpr, GPGME_KEYLIST_MODE_VALIDATE);
          if ((err = gpgme_op_keysign(ctx, _key, nullptr, 0, GPGME_KEYSIGN_LOCAL)))
          {
            throw pgp_exception(__FILE__, __LINE__, err);
          }
        }
        gpgme_key_release(_key);
      }
    }
  }
  if (retry)
  {
    verResult = verify_file_signature(file_to_be_verified, _signature);
    sig_sum = verResult->signatures->summary;
    isKeyMissing = (sig_sum & GPGME_SIGSUM_KEY_MISSING);
    isValid = (sig_sum & GPGME_SIGSUM_VALID) != 0;
  }
  json json;
  json["isValid"]         = isValid;
  json["isSigGood"]       = (sig_sum & GPGME_SIGSUM_GREEN)         != 0; // The signature is good.
  json["isSigBad"]        = (sig_sum & GPGME_SIGSUM_RED)           != 0; // The signature is bad.
  json["isKeyRevoked"]    = (sig_sum & GPGME_SIGSUM_KEY_REVOKED)   != 0; // One key has been revoked.
  json["isKeyExpired"]    = (sig_sum & GPGME_SIGSUM_KEY_EXPIRED)   != 0; // One key has expired.
  json["isSigExpired"]    = (sig_sum & GPGME_SIGSUM_SIG_EXPIRED)   != 0; // The signature has expired.
  json["isKeyNotFound"]   = isKeyMissing;                               // Can't verify: key missing.
  json["isCrlMissing"]    = (sig_sum & GPGME_SIGSUM_CRL_MISSING)   != 0; // CRL not available.
  json["isCrlTooOld"]     = (sig_sum & GPGME_SIGSUM_CRL_TOO_OLD)   != 0; // Available CRL is too old.
  json["isBadPolicy"]     = (sig_sum & GPGME_SIGSUM_BAD_POLICY)    != 0; // A policy was not met.
  json["isSysError"]      = (sig_sum & GPGME_SIGSUM_SYS_ERROR)     != 0; // A system error occurred.
  json["isTofuConflict"]  = (sig_sum & GPGME_SIGSUM_TOFU_CONFLICT) != 0; // Tofu conflict detected.
  json["isDeVS"]          = verResult->signatures->is_de_vs       != 0;
  json["fingerprint"]     = fpr;
  json["timestamp"]       = verResult->signatures->timestamp;
  json["sigValidity"]     = get_trust_level(verResult->signatures->validity);
  // get key from fpr and add email and other key information
  const list<map<string, string>> &public_keys = list_public_keys(&fpr);
  for (const auto &e : public_keys)
  {
    for (const auto &p : e)
    {
      json[p.first] = p.second;
    }
  }

  return json;
}

gpgme_verify_result_t open_pgp::verify_file_signature(const string &file_to_be_verified, string *_signature)
{
  auto *sig = _signature ? _signature : signature;
  if (!sig)
  {
    throw pgp_exception(__FILE__, __LINE__, "No signature set.");
  }
  // Create a data object pointing to the input file
  if ((err = gpgme_data_new_from_file(&in, file_to_be_verified.c_str(), 1)))
  {
    throw pgp_exception(__FILE__, __LINE__, err);
  }
  expand_sig_if_necessary(sig);
  gpgme_data_t s;
  if ((err = gpgme_data_new_from_mem(&s, sig->c_str(), sig->size(), 0)))
  {
    throw pgp_exception(__FILE__, __LINE__, err);
  }

  if ((err = gpgme_op_verify(ctx, s, in, nullptr)))
  {
    throw pgp_exception(__FILE__, __LINE__, err);
  }
  gpgme_data_release(s);
  gpgme_data_release(in);
  in = nullptr;

  return gpgme_op_verify_result(ctx);
}

void open_pgp::expand_sig_if_necessary(string *sig) const
{
  if (sig->find(BEGIN_PGP_SIGNATURE) == string::npos)
  {
    replace(sig->begin(), sig->end(), ' ', '\n');
    sig->insert((size_t) 0, BEGIN_PGP_SIGNATURE);
    sig->append(END_PGP_SIGNATURE);
  }
}

bool open_pgp::find_and_import_key(const string &fpr)
{
  gpgme_set_global_flag("auto-key-locate", key_server->c_str());

  gpgme_key_t _keys[2];
  _keys[0] = find_key(fpr, GPGME_KEYLIST_MODE_EXTERN);
  if (_keys[0] == nullptr)
  {
    throw pgp_exception(__FILE__, __LINE__, "The key with fingerprint "+fpr+" has not been found");
  }
  bool success;
  if ((success = check_trust(_keys[0])))
  {
    _keys[1] = nullptr;
    if (!_keys[0]->invalid)
    {
      if ((err = gpgme_op_import_keys(ctx, _keys)))
      {
        throw pgp_exception(__FILE__, __LINE__, err);
      }
      gpgme_import_result_t result = gpgme_op_import_result(ctx);
      success = result->imported != 0;
    }
    // trust key: sign it; GPGME seems to have no way to manipulate the trust level of a key
    if ((err = gpgme_op_keysign(ctx, _keys[0], nullptr, 0, GPGME_KEYSIGN_LOCAL)))
    {
      throw pgp_exception(__FILE__, __LINE__, err);
    }
  }
  gpgme_key_release(_keys[0]);

  return success;
}

bool open_pgp::check_trust(gpgme_key_t &_key)
{
  //todo check against known list of trusted key fingerprints to trust key automatically
  //todo check against individual trust path
  //todo check against trust path of keys in trusted key fingerprints
  cout << "Import PGP key " << _key->fpr << "?" << endl;
  cout << " owner name:  \"" << _key->uids->name << "\"" << endl;
  string *ownersEmail = _key->uids->email ? new string(_key->uids->email) : nullptr;
  cout << " owner email: \"" << *ownersEmail << "\", "
       << ((email != nullptr && *email != *ownersEmail) ? "the verified email in the seal is " + *email
                                                        : "which is the email in the seal.") << endl;
  if (_key->expired)
  {
    cout << " this key is expired" << endl;
  }
  if (_key->revoked)
  {
    cout << " this key is revoked" << endl;
  }
  if (_key->disabled)
  {
    cout << " this key is disabled" << endl;
  }
  bool trust = get_single_character_answer("Do you trust this key? [y/N] ", {'Y', 'N'}, 'N');

  return trust;
}

gpgme_key_t open_pgp::find_key(const string &fpr, gpgme_keylist_mode_t mode)
{
  gpgme_set_keylist_mode(ctx, mode);
  gpgme_key_t _k = nullptr;
  err = gpgme_op_keylist_start(ctx, fpr.c_str(), 0);
  while (!err)
  {
    gpgme_key_t _key;
    err = gpgme_op_keylist_next(ctx, &_key);
    if (!err)
    {
      if (_key->invalid)
      {
        gpgme_key_release(_key);
      }
      else
      {
        _k = _key;
      }
    }
  }
  if (gpg_err_code(err) != GPG_ERR_EOF)
  {
    throw pgp_exception(__FILE__, __LINE__, err);
  }
  return _k;
}

bool open_pgp::export_key(const string &fpr)
{
  bool success = is_key_exported(fpr);
  if (!success)
  {
    gpgme_key_t _keys[2];
    if ((success = ((_keys[0] = find_key(fpr)) != nullptr)))
    {
      gpgme_set_global_flag("auto-key-locate", key_server->c_str());

      if ((err = gpgme_op_export_keys(ctx, _keys, GPGME_KEYLIST_MODE_EXTERN, nullptr)))
      {
        throw pgp_exception(__FILE__, __LINE__, err);
      }
      fflush(nullptr);

      gpgme_key_release(_keys[0]);
      success = is_key_exported(fpr);
    }
  }
  return success;
}

bool open_pgp::is_key_exported(const string &fpr)
{
  string *exported_key_ids = properties->get("exportedKeyIds");
  bool exported = true;
  if ((exported_key_ids == nullptr) ||
      (exported_key_ids->find(fpr) == string::npos))
  {
    gpgme_key_t _key = find_key(fpr, GPGME_KEYLIST_MODE_EXTERN);
    if ((exported = (_key != nullptr)))
    {
      gpgme_key_release(_key);
      properties->put("exportedKeyIds", *(exported_key_ids ? &exported_key_ids->append("," + fpr) : new string(fpr)));
    }
  }
  delete exported_key_ids;

  return exported;
}
