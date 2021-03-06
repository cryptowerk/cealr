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

#ifndef CEALR_MESSAGE_DIGEST_H
#define CEALR_MESSAGE_DIGEST_H

#include <string>
#include <list>
#include <vector>
#include <openssl/sha.h>

using namespace std;

class sha256_digest;

/*!
Abstract message digest class. Serves as helper to rewrite the java implementation of smart stamps in c++.
*/
class MessageDigest
{
public:
  virtual ~MessageDigest() = default;

  virtual void update(void *data, size_t size) = 0;

  void update(list<vector<unsigned char>> list_data);

  virtual unsigned char *digest() = 0;

  virtual size_t digest_length() = 0;
};

class sha256_digest : public MessageDigest
{
  SHA256_CTX *sha256_ctx;

public:
  sha256_digest();

  ~sha256_digest() override;

  void update(void *data, size_t size) override;

  unsigned char *digest() override;

  size_t digest_length() override;
};

#endif //CEALR_MESSAGE_DIGEST_H
