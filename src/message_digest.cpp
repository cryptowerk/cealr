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

#include "message_digest.h"

MessageDigest *MessageDigest::getInstance(const string &inst)
{
  return new sha256_digest();
}

sha256_digest::sha256_digest()
{
  sha256_ctx = new SHA256_CTX;
  SHA256_Init(sha256_ctx);
}

void sha256_digest::update(void *data, size_t size)
{
  SHA256_Update(sha256_ctx, data, size);
}

unsigned char *sha256_digest::digest()
{
  auto *hash = new unsigned char[SHA256_DIGEST_LENGTH];
  SHA256_Final(hash, sha256_ctx);
  return hash;
}

size_t sha256_digest::getDigestLength()
{
  return SHA256_DIGEST_LENGTH;
}

sha256_digest::~sha256_digest()
{
  delete sha256_ctx;
}
