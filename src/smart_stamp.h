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
#include "serialized_data_format.h"
#include "base64.h"

#include <gpgme.h>
#include <nlohmann/json.hpp>

#include <algorithm>
//#include <cmath>


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
#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"
  OPTIMIZED_MERKLE_TREE,
  BALANCED_CONCURRENT_MERKLE_TREE
#pragma clang diagnostic pop
};

class SmartStamp
{
//private:
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

//  bool equals(Object obj)
//  {
//    if (obj != null && obj instanceof
//    BlockchainDescriptor) {
//      BlockchainDescriptor
//          cmp = (BlockchainDescriptor) obj;
//      return blockchainGeneralName.equals(cmp.blockchainGeneralName) && instanceName.equals(cmp.instanceName);
//    }
//    return false;
//  }

//  int hashCode()
//  {
//    final int prime = 31;
//    int result = 1;
//    //if (blockchainGeneralName==null)
//    //  System.out.println();
//    result = prime * result + blockchainGeneralName.hashCode();
//    result = prime * result + instanceName.hashCode();
//    return result;
//  }

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
    virtual ~Operation()
    {
    }
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

    ~OperationEvaluator(){
      delete digest;
      delete optUsrProvAnchorInBC;
      delete optLookedUpAnchorInBlockchain;
      delete optLookedUpVerificationSources;
      delete additionalInfo;
      delete verificationSources;
      delete optInstructions;
    }

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
    void instruct(string instruction)
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
    unsigned char docHash[SHA256_DIGEST_LENGTH];

  public:
    DocHash(unsigned char *_docHash)
    {
      memcpy(docHash, _docHash, SHA256_DIGEST_LENGTH);
    }

    virtual ~DocHash()
    {
    }

    void execute(OperationEvaluator &vm) const override
    {
      vm.instruct(
          "Check that hash in SmartStamp " + to_hex(vm.accu, SHA256_DIGEST_LENGTH) + " equals actual document hash " +
          to_hex(docHash, SHA256_DIGEST_LENGTH) + ".");
      if (memcmp(vm.accu, docHash, SHA256_DIGEST_LENGTH))
      {
        throw SmartStampError(__FILE__, __LINE__,
                             "Original document hash does not equal document hash contained in SmartStamp.");
      }
      vm.setOrigDocComparisonDone(true);
    }

//    void write(sdf_ostream out)
//    {
//      out.writeRaw(docHash, OPCODE_DOC_SHA256);
//    }
  };

  class Append: public Operation
  {
  private:
    unsigned char hash[SHA256_DIGEST_LENGTH];

  public:
    Append(unsigned char *_hash)
    {
      memcpy(hash, _hash, SHA256_DIGEST_LENGTH);
    }

    virtual ~Append()
    {
    }

    void execute(OperationEvaluator &vm) const override;

//    void write(sdf_ostream out);
  };

  class Prepend: public Operation
  {
  private:
    unsigned char hash[SHA256_DIGEST_LENGTH];

  public:

    Prepend(unsigned char *_hash)
    {
      memcpy(hash, _hash, SHA256_DIGEST_LENGTH);
    }

    virtual ~Prepend()
    {
    }

    void execute(OperationEvaluator &vm) const override
    {
      char combo[2*SHA256_DIGEST_LENGTH];
      memcpy(combo, hash, SHA256_DIGEST_LENGTH);
      memcpy(combo+SHA256_DIGEST_LENGTH, vm.accu, SHA256_DIGEST_LENGTH);
      memcpy(vm.accu, vm.hash(combo, 2*SHA256_DIGEST_LENGTH), SHA256_DIGEST_LENGTH);
      vm.instruct("Prepend " + to_hex(hash, SHA256_DIGEST_LENGTH) + " and hash it, resulting in " + to_hex(vm.accu, SHA256_DIGEST_LENGTH) + ".");
    }

//    void write(sdf_ostream out)
//    {
//      out.write(OPCODE_PREPEND_THEN_SHA256);
//      writeSHA256(out, hash);
//    }
  };

  class Anchor: public Operation
  {
  private:
    unsigned char hash[SHA256_DIGEST_LENGTH];
  public:
    Anchor(unsigned char *_hash)
    {
      memcpy(hash, _hash, SHA256_DIGEST_LENGTH);
    }

    ~Anchor()
    {
    }

    void execute(OperationEvaluator &vm) const override
    {
      vm.instruct("Check that provided anchor " + to_hex(hash, SHA256_DIGEST_LENGTH) + " equals calculated anchor " +
                  to_hex(vm.accu, SHA256_DIGEST_LENGTH) + ".");
      if (memcmp(vm.accu, hash, SHA256_DIGEST_LENGTH) != 0) {
        throw SmartStampError(__FILE__, __LINE__, "Calculated anchor does not equal stored anchor in SmartStamp.");
      }
      string str("AnchorInStamp");
      vm.verificationSourcesAdd(new VerificationSource(str));
      if (vm.optUsrProvAnchorInBC)
      {
        if (memcmp(vm.accu, vm.optUsrProvAnchorInBC, SHA256_DIGEST_LENGTH))
        {
          throw SmartStampError(__FILE__, __LINE__, "Calculated anchor does not equal provided anchor in blockchain.");
        }
        string str1("AnchorFromUser");
        vm.verificationSourcesAdd(new VerificationSource(str1));
      }
      vm.anchorComparisonDone = true;
      memcpy(vm.optContainedAnchor, hash, SHA256_DIGEST_LENGTH);
      if (vm.optLookedUpAnchorInBlockchain != nullptr)
      {
        if (memcmp(vm.accu, vm.optLookedUpAnchorInBlockchain, SHA256_DIGEST_LENGTH))
        {
          throw SmartStampError(__FILE__, __LINE__, "Calculated anchor does not equal looked up anchor in blockchain.");
        }
        if (vm.optLookedUpVerificationSources != nullptr) // paranoia
        {
          vm.verificationSourcesAddAll(vm.optLookedUpVerificationSources);
        }
      }
    }

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
    long insertedIntoBlockchainAt;

  public:
    Blockchain(BlockchainDescriptor *_blockChainDesc, string _blockChainId, long _insertedIntoBlockchainAt)
    {
      blockChainDesc = _blockChainDesc;
      blockChainId = _blockChainId;
      insertedIntoBlockchainAt = _insertedIntoBlockchainAt;
    }

    virtual ~Blockchain()
    {
      delete blockChainDesc;
    }

    void execute(OperationEvaluator &vm) const override
    {
      string msg="Registered in blockchain "+blockChainDesc->toString()+" using TxId or Id "+blockChainId+" at "+format_time(insertedIntoBlockchainAt/1000, "yyyy-MM-dd HH:mm:ss z");
      vm.additionalInfo->append(msg+"\n");
      vm.instruct(msg);

//      if (vm.optUsrProvAnchorInBC==nullptr && vm.optBCLookup!=nullptr) {
//        char *anchorInBlockchain = vm.optBCLookup.findAnchor(blockChainDesc, blockChainId);
//        if (anchorInBlockchain != nullptr)
//        {
//          if (vm.optLookedUpAnchorInBlockchain != nullptr &&
//              !Arrays.equals(vm.optLookedUpAnchorInBlockchain, anchorInBlockchain))
//            throw SmartStampError(
//                "Multiple anchors found during blockchain lookup which are not equal to each other.");
//          vm.optLookedUpAnchorInBlockchain = anchorInBlockchain;
//          if (vm.optLookedUpVerificationSources == nullptr)
//            vm.optLookedUpVerificationSources = new LinkedList<>();
//          vm.optLookedUpVerificationSources.add(
//              new VerificationSource(vm.optBCLookup.getName(), blockChainDesc, blockChainId));
//          if (vm.optContainedAnchor != nullptr)
//          {
//            if (!Arrays.equals(anchorInBlockchain, vm.optContainedAnchor))
//              throw SmartStampError(__FILE__, __LINE__, "Contained anchor does not equal looked up anchor in blockchain.");
//            vm.verificationSources.addAll(vm.optLookedUpVerificationSources);
//          }
//        }
//        else
//        {
//          throw SmartStampError(__FILE__, __LINE__, "Cannot look up anchor in blockchain.");
//        }
//      }
    }

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
    DocumentInfo(string *optLookupInfo, string *optName, string *optContentType)
    {
      this->optLookupInfo = optLookupInfo;
      this->optName = optName;
      this->optContentType = optContentType;
    }

    virtual ~DocumentInfo()
    {
      delete optLookupInfo;
      delete optName;
      delete optContentType;
    }

    void execute(OperationEvaluator &vm) const override
    {
      string infoText;
      if (optLookupInfo != nullptr)
        infoText.append("Document lookup info=" + *optLookupInfo + "\n");
      if (optName != nullptr)
        infoText.append("Document name=" + *optName + "\n");
      if (optContentType != nullptr)
        infoText.append("Document content type=" + *optContentType + "\n");

      vm.additionalInfo->append(infoText);
      if (!infoText.empty())
        vm.instruct(infoText);
    }

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
    SealedMetaData(string *data, list<vector<char>> *metaDataStamps)
    {
      this->data = data;
      this->metaDataStamps = metaDataStamps;
    }

    virtual ~SealedMetaData()
    {
      delete data;
      delete metaDataStamps;
    }

    void execute(OperationEvaluator &vm) const override
    {
      string infoText;
      string str;
      for (vector<char> pChar:*metaDataStamps){
        str+= to_hex((unsigned char*)&pChar[0], static_cast<int>(pChar.size()));
      }
      infoText.append("Sealed meta data: contents=(" + *data + "), meta data SmartStamps=(" + str + ")\n");
//    string infoText=info.toString();
      vm.additionalInfo->append(infoText);
      if (!infoText.empty())
      {
        vm.instruct(infoText);
      }
    }

//    void write(sdf_ostream out)
//    {
//      out.write(OPCODE_SEALEDMETADATA);
//      out.write(data);
//      out.write(metaDataStamps);
//    }
  };

  vector<char> *data;
  bool parseTried = false;
  unsigned char *docHash = nullptr;
  list<Operation *> *operations = nullptr;

//public:
//  SmartStamp(char *data)
//  {
//    data = data;
//  }

  SmartStamp(const string &textRepresentation)
  {
    data = base64::decode(textRepresentation);
  }

  ~SmartStamp()
  {
    delete data;
    delete docHash;
    delete operations;
  }

  void parse()
  {
    operations = new list<Operation*>();
    parseTried = true;
    bool headerOk = false;
    int storedVersion = -1;
    ByteArrayInputStream inRaw(data);

    if (data->size() >= 3 &&
        inRaw.read() == 'S' &&
        inRaw.read() == 'T')
    {
      storedVersion = inRaw.read();
      if (storedVersion >= MIN_VERSION && storedVersion <= MAX_VERSION)
      {
        headerOk = true;
      }
    }
    if (!headerOk)
    {
      throw SmartStampError(__FILE__, __LINE__, "SmartStamp has an invalid header.");
    }
    sdf_istream in(&inRaw, storedVersion < 2 ? _Compatibility::SuppressReadingOfHeader
                                             : _Compatibility::Default);

    BundleMethod bundleMethod = in.supports(8) ? static_cast<BundleMethod>((int) in.readInt()) :
                                BundleMethod::BALANCED_MERKLE_TREE;
    for (bool finished = false; !finished;)
    {
      int opcode = in.readByte();
      Operation *operation;
      switch (opcode)
      {
        case OPCODE_END:
          finished = true;
          operation = nullptr;
          break;

        case OPCODE_DOC_SHA256:
          docHash = readSHA256(&in);
          operation = new DocHash(docHash);
          break;

        case OPCODE_APPEND_THEN_SHA256:
          operation = new Append(readSHA256(&in));
          break;

        case OPCODE_PREPEND_THEN_SHA256:
          operation = new Prepend(readSHA256(&in));
          break;

        case OPCODE_ANCHOR_SHA256:
          operation = new Anchor(readSHA256(&in));
          break;

        case OPCODE_BLOCKCHAIN:
        {
          BlockchainDescriptor *desc = in.supports(3) ?
                                       new BlockchainDescriptor(in) :
                                       new BlockchainDescriptor(*in.readString(), (string &) "unknown");
          //string blockChainName=in.readString();
          string *blockChainId = in.readString();
          long insertedIntoBlockchainAt = in.readInt();
          operation = new Blockchain(desc, *blockChainId, insertedIntoBlockchainAt);
          break;
        }
        case OPCODE_DOCUMENTINFO:
        {
          string *optReferenceId = in.readOptString();
          string *optName = in.readOptString();
          string *optContentType = in.readOptString();
          operation = new DocumentInfo(optReferenceId, optName, optContentType);
          break;
        }
        case OPCODE_SEALEDMETADATA:
        {
          string *metaData = in.readString();
          list<vector<char>> *metaDataStamps = in.readList(Reader<vector<char>>(&in));
          operation = new SealedMetaData(metaData, metaDataStamps);
          break;
        }
        default:
          throw SmartStampError(__FILE__, __LINE__, "Illegal opcode in SmartStamp.");
      }
      if (operation != nullptr)
      {
        operations->push_back(operation);
//        delete operation;
      }
    }
  }

  void initFields()
  {
    if (!parseTried)
      parse();
  }

//  static void writeSHA256(sdf_ostream *out, unsigned char hash[SHA256_DIGEST_LENGTH])
//  {
//    if (hash.length != 256 / 8)
//      throw IOException(__FILE__, __LINE__, "Illegal length of hash.");
//    out->writeRaw(hash, SHA256_DIGEST_LENGTH);
//  }

  unsigned char *readSHA256(sdf_istream *in)
  {
    auto *hash = new unsigned char[SHA256_DIGEST_LENGTH];
    in->readRaw(hash, SHA256_DIGEST_LENGTH);
    return hash;
  }

  json toJson()
  {
    json json;
    json["data"] = base64::encode(*data);
    return json;
  }

  vector<char> *toRawData()
  {
    return data;
  }

  unsigned char *getDocHash()
  {
    initFields();
    if (docHash == nullptr)
    {
      throw SmartStampError(__FILE__, __LINE__, "Missing docHash in SmartStamp.");
    }
    return docHash;
  }

  VerificationResult *verifyByContents(char *documentContents, char *optHashInBlockchain, bool provideInstructions)
  {
    OperationEvaluator *vm = new OperationEvaluator();
    return verifyByHashHelper(vm, vm->hash(documentContents, SHA256_DIGEST_LENGTH), provideInstructions);
  }

  VerificationResult *verifyByHash(unsigned char *documentHash, char *optHashInBlockchain, bool provideInstructions)
  {
    auto *vm = new OperationEvaluator();
    return verifyByHashHelper(vm, documentHash, provideInstructions);
  }

  VerificationResult *verifyByHashHelper(OperationEvaluator *vm, unsigned char *documentHash, bool provideInstructions)
  {
    initFields();
    return vm->verify(operations, documentHash, nullptr, provideInstructions);
  }

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
