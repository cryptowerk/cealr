#include <utility>

//
// Created by Olaf Zumpe on 9/5/18.
//

#ifndef CEALR_SMART_STAMP_H
#define CEALR_SMART_STAMP_H

#include <list>
#include <map>
#include "Properties.h"
#include "file_util.h"
#include "message_digest.h"
#include "serialized_data_format.hpp"
#include "base64.h"

#include <gpgme.h>
#include <nlohmann/json.hpp>

#include <algorithm>


using json = nlohmann::json;

using namespace std;

#define OPCODE_DOC_SHA256           ((char)1)
#define OPCODE_APPEND_THEN_SHA256   ((char)2)
#define OPCODE_PREPEND_THEN_SHA256  ((char)3)
#define OPCODE_ANCHOR_SHA256        ((char)4)
#define OPCODE_BLOCKCHAIN           ((char)5)
#define OPCODE_END                  ((char)6)
#define OPCODE_DOCUMENTINFO         ((char)7)
#define OPCODE_SEALEDMETADATA       ((char)8)

#define MAX_VERSION ((char)5)
#define MIN_VERSION ((char)1)

class SmartStampError : public exception
{
private:
  runtime_error _what;

public:
  SmartStampError(const string &file, const int line, const string &errStr) : _what(
      ("" + file + ":" + to_string(line) + ": " + errStr).c_str()) {}

  const char *what()
  {
    return _what.what();
  }
};

template <>
class Reader<vector<char>>
{
  sdf_istream *in;
public:
  explicit Reader<vector<char>>(sdf_istream *_in)
  {
    in = _in;
  }

  vector<char> read()
  {
    return *(in->readByteBlock());
  }
};

enum BundleMethod
{
  BALANCED_MERKLE_TREE,
  OPTIMIZED_MERKLE_TREE,
  BALANCED_CONCURRENT_MERKLE_TREE
};

class SmartStamp
{
public:
  class OperationEvaluator;

  class BlockchainDescriptor
  {
  public:
    string *blockchainGeneralName;
    string *instanceName;

    BlockchainDescriptor(string &_blockchainGeneralName, string &_instanceName);

    void init(string &_blockchainGeneralName, string &_instanceName);

//    void write(sdf_ostream &out);

    explicit BlockchainDescriptor(sdf_istream in);

    json toJson();

    string toString() {
      return *blockchainGeneralName+(!instanceName->length()? "":"."+*instanceName);
    }

  };

  class VerificationSource
  {
  private:
    string sourceName;
    BlockchainDescriptor *optBlockChainDesc;
    string *optBlockChainId;

  public:
    explicit VerificationSource(string &_sourceName);

    VerificationSource(string &_sourceName, BlockchainDescriptor *_blockChainDesc, string *_blockChainId);

    json toJson();
  };

  class VerificationResult
  {
  private:
    bool verified;
    list<VerificationSource> verificationSources;
    string additionalInfo;
    string *optInstructions;

  public:
    VerificationResult(bool _verified, list<VerificationSource> _verificationSources, string _additionalInfo,
                       string *_optInstructions);

    json toJson();

    bool hasBeenVerified()
    {
      return verified;
    }

    string getAdditionalInfo()
    {
      return additionalInfo;
    }
  };

  class Operation
  {
  public:
    virtual void execute(OperationEvaluator &vm) const = 0;
//    virtual void write(sdf_ostream out) = 0;
    virtual ~Operation() = default;
  };

  class OperationEvaluator
  {
//  private:
  public:  //todo Encapsulate!
    MessageDigest *digest;
    bool origDocComparisonDone;
    bool anchorComparisonDone;
    char *optUsrProvAnchorInBC;
    char *optLookedUpAnchorInBlockchain;
    list<VerificationSource> *optLookedUpVerificationSources;
    string *additionalInfo;
    list<VerificationSource> *verificationSources;
    string *optInstructions;

    unsigned char optContainedAnchor[SHA256_DIGEST_LENGTH];

//  public:
    unsigned char accu[SHA256_DIGEST_LENGTH];

    OperationEvaluator();

    ~OperationEvaluator();

    VerificationResult *verify(list<Operation *> *operations,
                               unsigned char *origDocHash,
                               char *optoptBCAnchor,
                               bool provideInstructions);

    unsigned char *hash(char *data, size_t size)
    {
      digest->update(data, size);
      return digest->digest(); // reset() is implied
    }

    int getHashLength()
    {
      return static_cast<int>(digest->getDigestLength());
    }

    /* used for lazy evaluation in order to not waste time calculating the parameter if it's not required */
    void instruct(const string &instruction)
    {
      if (optInstructions != nullptr)
      {
        optInstructions->append(instruction);
        if (optInstructions->at(optInstructions->size()-1)!='\n')
          optInstructions->append("\n");
      }
    }

    void setOrigDocComparisonDone(bool b){
      origDocComparisonDone = true;
    }

    void verificationSourcesAdd(VerificationSource *vs){
      verificationSources->push_back(*vs);
    }

    void verificationSourcesAddAll(list<VerificationSource> *pList) {
      for (VerificationSource vs:*pList){
        verificationSourcesAdd(&vs);
      }
    }
  };

  class DocHash : public Operation
  {
  private:
    unsigned char docHash[SHA256_DIGEST_LENGTH]{};

  public:
    explicit DocHash(unsigned char *_docHash)
    {
      memcpy(docHash, _docHash, SHA256_DIGEST_LENGTH);
    }

    ~DocHash() override = default;

    void execute(OperationEvaluator &vm) const override;

//    void write(sdf_ostream out)
//    {
//      out.writeRaw(docHash, OPCODE_DOC_SHA256);
//    }
  };

  class Append: public Operation
  {
  private:
    unsigned char hash[SHA256_DIGEST_LENGTH]{};

  public:
    explicit Append(unsigned char *_hash);

    ~Append() override = default;

    void execute(OperationEvaluator &vm) const override;

//    void write(sdf_ostream out);
  };

  class Prepend: public Operation
  {
  private:
    unsigned char hash[SHA256_DIGEST_LENGTH]{};

  public:

    explicit Prepend(unsigned char *_hash);

    ~Prepend() override = default;

    void execute(OperationEvaluator &vm) const override;

//    void write(sdf_ostream out)
//    {
//      out.write(OPCODE_PREPEND_THEN_SHA256);
//      writeSHA256(out, hash);
//    }
  };

  class Anchor: public Operation
  {
  private:
    unsigned char hash[SHA256_DIGEST_LENGTH]{};
  public:
    explicit Anchor(unsigned char *_hash);

    ~Anchor() override = default;

    void execute(OperationEvaluator &vm) const override;

    //    void write(sdf_ostream out)
//    {
//      out.write(OPCODE_ANCHOR_SHA256);
//      writeSHA256(out, hash);
//    }
  };

  class Blockchain: public Operation
  {
  private:
    BlockchainDescriptor *blockChainDesc;
    string blockChainId;
    time_t insertedIntoBlockchainAt;

  public:
    Blockchain(BlockchainDescriptor *_blockChainDesc, string _blockChainId, long _insertedIntoBlockchainAt);

    ~Blockchain() override;

    void execute(OperationEvaluator &vm) const override;

    time_t getInsertedIntoBlockchainAt() const;

    const string &getBlockChainId() const;

    BlockchainDescriptor *getBlockChainDesc() const;


//    void write(sdf_ostream out)
//    {
//      out.write(OPCODE_BLOCKCHAIN);
//      blockChainDesc->write(out);
//      out.write(blockChainId);
//      out.writeInt(insertedIntoBlockchainAt);
//    }
  };

  class DocumentInfo: public Operation
  {
  private:
    string *optLookupInfo; // = optReferenceId
    string *optName;
    string *optContentType;

  public:
    DocumentInfo(string *_optLookupInfo, string *_optName, string *_optContentType);

    ~DocumentInfo() override;

    void execute(OperationEvaluator &vm) const override;

//    void write(sdf_ostream out)
//    {
//      out.write(OPCODE_DOCUMENTINFO);
//      out.writeOpt(optLookupInfo);
//      out.writeOpt(optName);
//      out.writeOpt(optContentType);
//    }
  };

  class SealedMetaData: public Operation
  {
  private:
    string *data;
    list<vector<char>> *metaDataStamps;

  public:
    SealedMetaData(string *_data, list<vector<char>> *_metaDataStamps);

    ~SealedMetaData() override;

    string *getData() const;

    list<vector<char>> *getMetaDataStamps() const;

    void execute(OperationEvaluator &vm) const override;

//    void write(sdf_ostream out)
//    {
//      out.write(OPCODE_SEALEDMETADATA);
//      out.write(data);
//      out.write(metaDataStamps);
//    }
  };

private:
  vector<char>      *data;
  bool               parseTried     = false;
  unsigned char     *docHash        = nullptr;
  unsigned char     *rootHash       = nullptr;
  list<Operation*>  *operations     = nullptr;
  Blockchain        *blockchain     = nullptr;
  DocumentInfo      *documentInfo   = nullptr;
  SealedMetaData    *sealedMetaData = nullptr;
  BundleMethod       bundleMethod   = BundleMethod::BALANCED_MERKLE_TREE;


public:
//  SmartStamp(vector<char> *_data)
//  {
//    data = _data;
//  }

  explicit SmartStamp(const string &textRepresentation);

  explicit SmartStamp(const vector<char> _data);

  ~SmartStamp();

public:
  void parse();

  void initFields();

//  static void writeSHA256(sdf_ostream *out, unsigned char hash[SHA256_DIGEST_LENGTH])
//  {
//    if (hash.length != 256 / 8)
//      throw IOException(__FILE__, __LINE__, "Illegal length of hash.");
//    out->writeRaw(hash, SHA256_DIGEST_LENGTH);
//  }

  unsigned char *readSHA256(sdf_istream *in);

  json toJson();

  vector<char> *toRawData();

  unsigned char *getDocHash();

  unsigned char *getRootHash() const;

  list<Operation *> *getOperations() const;

  Blockchain *getBlockchain() const;

  DocumentInfo *getDocumentInfo() const;

  SealedMetaData *getSealedMetaData() const;

  BundleMethod getBundleMethod() const;


  VerificationResult *verifyByContents(char *documentContents, char *optHashInBlockchain, bool provideInstructions);

  VerificationResult *verifyByHash(unsigned char *documentHash, char *optHashInBlockchain, bool provideInstructions);

  VerificationResult *verifyByHashHelper(OperationEvaluator *vm, unsigned char *documentHash, bool provideInstructions);

//  void appendTo(SmartStampCreator stampCreator)
//  {
//    initFields();
//    for (Operation operation: operations)
//    {
//      stampCreator.add(operation); // by reference at the moment, alternative: clone and add
//      //operation.appendTo(stampCreator);
//    }
//  }
//
//  void write(sdf_ostream out) {
//    out.writeByteBlock(data);
//  }

//  SmartStamp(sdf_istream *in) {
//    this(in->readByteBlock());
//  }
};

//bool verifySmartStamp(string smartStampTextualRepresentation)
//{
//  SmartStamp *smartStamp = new SmartStamp(smartStampTextualRepresentation);
//  SmartStamp->VerificationResult
//  verificationResult;
//  if (docHashString)
//  {
//    char *documentHash = fromHex(docHashString);
//    verificationResult = smartStamp->verifyByHash(documentHash, anchorInBlockchain, null, true);
//  }
//  else
//  {
//    final
//    byte[]
//    docData = Files.readAllBytes(Paths.get(docHashOrFile));
//    verificationResult = smartStamp->verifyByContents(docData, anchorInBlockchain, null, true);
//  }
//  System.out.println(
//      "Your document " + (verificationResult.hasBeenVerified() ? "has been successfully" : "could not be") +
//      " verified.");
//  String info = verificationResult.getAdditionalInfo();
//  if (!info.isEmpty())
//    System.out.print(info);
//}

#endif //CEALR_SMART_STAMP_H

