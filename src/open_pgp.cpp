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
#include "open_pgp.h"

open_pgp::open_pgp(gpgme_sig_mode_t _sig_mode, Properties *_properties, const string *email_addr)
{
  sig_mode    = _sig_mode;
  email       = email_addr;
  properties  = _properties;
  key         = nullptr;
  signature   = nullptr;
  in          = nullptr;
  out         = nullptr;
  key_id      = nullptr;
  key_name    = nullptr;
  key_email   = nullptr;
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
//  gpgme_engine_info_t x = gpgme_ctx_get_engine_info(ctx);

  // Set the context to textmode
  gpgme_set_textmode(ctx, 1);
  // Enable ASCII armor on the context
  gpgme_set_armor(ctx, 1);

  key_server = properties->get("keyServer", new string("pgp.mit.edu"), false);
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
  // Read the contents of "out" and place it into buf

  // todo something like this method may work instead the vector

  size_t size/*  = (int) sig.size()*/;
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

//  todo check if this->key is uploaded on the default key server and upload it, if not (maybe store the key ID as uploaded in the properties?).
//    if (*keyId!=*properties->get("keyId")) {
//        properties->put("keyId", *keyId);
//    }
  return *signature;
}

void open_pgp::select_best_signing_key()
{
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
      if (canSign(_key))
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
            unsigned int nKeySigs = count_signatures(_key);
            if (nKeySigs >= most_key_signatures)
            {
              if (nKeySigs == most_key_signatures)
              {
                // todo use key with most information
              }
              else
              {
                most_key_signatures = nKeySigs;
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
    throw pgp_exception(__FILE__, __LINE__, "GnuPG has no signing key installed.");
  }
}

unsigned int open_pgp::count_signatures(_gpgme_key *const _key) const
{
  unsigned int n_key_sigs = 0;
  gpgme_user_id_t uid = _key->uids;
  while (uid)
  {
    gpgme_user_id_t next_uid = uid->next;
    gpgme_key_sig_t key_sig = uid->signatures;

    while (key_sig)
    {
      gpgme_key_sig_t next_key_sig = key_sig->next;
      n_key_sigs++;
      key_sig = next_key_sig;
    }
    uid = next_uid;
  }
  return n_key_sigs;
}

list<map<string, string>> open_pgp::list_keys(const string *opt_pattern, int is_private)
{
  auto result = new list<map<string, string>>;
  err = gpgme_op_keylist_start(ctx, opt_pattern ? opt_pattern->c_str() : nullptr, is_private);
  while (!err)
  {
    gpgme_key_t key;
    err = gpgme_op_keylist_next(ctx, &key);
    if (!err)
    {
      if (!key->invalid && key->subkeys->can_sign)
      {
        auto k = new map<string, string>;
        (*k)["keyId"] = key->subkeys->keyid;
        if (key->uids && key->uids->name)
        {
          (*k)["name"] = key->uids->name;
        }
        if (key->uids && key->uids->email)
        {
          (*k)["email"] = key->uids->email;
        }
        result->push_back(*k);
      }
      gpgme_key_release(key);
    }
  }
  if (gpg_err_code(err) != GPG_ERR_EOF)
  {
    fprintf(stderr, "can not list keys: %s\n", gpgme_strerror(err));
    exit(1);
  }
  return *result;
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

bool open_pgp::canSign(gpgme_key_t key)
{
  // bad practice to use main key for signing
  bool canSign = static_cast<bool>(key->can_sign);
  gpgme_subkey_t subKey = key->subkeys;
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

//todo implement searching, downloading, verifying, installing, trusting public key by key ID


//todo implement generating key pair and uploading public key

// verify signature
json open_pgp::verify(const string file_to_be_verified, string *_signature)
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
  expand_sig_if_neccesary(sig);
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
  gpgme_verify_result_t verResult = gpgme_op_verify_result(ctx);
  if (!(verResult->signatures->summary & GPGME_SIGSUM_VALID))
  {
    throw pgp_exception(__FILE__, __LINE__, "invalid signature.");
  }
  json json;
  json["isValid"] = (verResult->signatures->summary & GPGME_SIGSUM_VALID) != 0;
  json["isDeVS"] = verResult->signatures->is_de_vs != 0;
  string fpr = verResult->signatures->fpr;
  json["fingerprint"] = fpr;
  json["timestamp"] = verResult->signatures->timestamp;
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

void open_pgp::expand_sig_if_neccesary(string *sig) const
{
  if (sig->find(BEGIN_PGP_SIGNATURE) == string::npos)
  {
    replace(sig->begin(), sig->end(), ' ', '\n');
    sig->insert((size_t) 0, BEGIN_PGP_SIGNATURE);
    sig->append(END_PGP_SIGNATURE);
  }
}
