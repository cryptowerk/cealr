//
// Created by Olaf Zumpe on 9/6/18.
//

#ifndef CEALR_MESSAGE_DIGEST_H
#define CEALR_MESSAGE_DIGEST_H

#include <string>
#include <openssl/sha.h>

using namespace std;

class sha256_digest;

class MessageDigest
{
public:
  static MessageDigest *getInstance(const string &inst);
  
  virtual ~MessageDigest()
  {
  }

  virtual void update(void *data, size_t size) = 0;
  virtual unsigned char *digest() = 0;
  virtual size_t getDigestLength() = 0;
};

class sha256_digest: public MessageDigest {
  SHA256_CTX *sha256_ctx;

public:
  sha256_digest();

  ~sha256_digest() override;

  void update(void *data, size_t size) override;

  unsigned char *digest() override;

  size_t getDigestLength() override;
 
};

#endif //CEALR_MESSAGE_DIGEST_H
