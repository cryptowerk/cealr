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

#include <utility>

#include <utility>

//
// Created by Olaf Zumpe on 9/5/18.
//

#include "smart_stamp.h"

SmartStamp::SmartStamp(const string &textRepresentation)
{
  data = base64::decode(textRepresentation);
}

SmartStamp::SmartStamp(vector<char> _data)
{
  data = new vector<char>(_data.begin(), _data.end());
}

SmartStamp::~SmartStamp()
{
  delete data;
  delete docHash;
  delete rootHash;
//  delete blockchain;
//  delete documentInfo;
//  delete sealedMetaData;
  for (SmartStamp::Operation *o:*operations){
    delete o;
  }
  delete operations;
}

void SmartStamp::parse()
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

  bundleMethod = in.supports(8) ? static_cast<BundleMethod>((int) in.readInt()) :
                              BundleMethod::BALANCED_MERKLE_TREE;
  for (bool finished = false; !finished;)
  {
    int opcode = in.readByte();
    Operation *operation;
    switch (opcode)
    {
      case OPCODE_END:
        finished  = true;
        operation = nullptr;
        break;

      case OPCODE_DOC_SHA256:
        docHash   = readSHA256(&in);
        operation = new DocHash(docHash);
        break;

      case OPCODE_APPEND_THEN_SHA256:
        operation = new Append(readSHA256(&in));
        break;

      case OPCODE_PREPEND_THEN_SHA256:
        operation = new Prepend(readSHA256(&in));
        break;

      case OPCODE_ANCHOR_SHA256:
        rootHash  = readSHA256(&in);
        operation = new Anchor(rootHash);
        break;

      case OPCODE_BLOCKCHAIN:
      {
        BlockchainDescriptor *desc      = in.supports(3) ?
                                          new BlockchainDescriptor(in) :
                                          new BlockchainDescriptor(*in.readString(), (string &) "unknown");
        string *blockChainId            = in.readString();
        time_t insertedIntoBlockchainAt = in.readInt();
        blockchain                      = new Blockchain(desc, *blockChainId, insertedIntoBlockchainAt);
        operation                       = blockchain;
        break;
      }
      case OPCODE_DOCUMENTINFO:
      {
        string *optReferenceId          = in.readOptString();
        string *optName                 = in.readOptString();
        string *optContentType          = in.readOptString();
        documentInfo                    = new DocumentInfo(optReferenceId, optName, optContentType);
        operation                       = documentInfo;
        break;
      }
      case OPCODE_SEALEDMETADATA:
      {
        string *metaData                = in.readString();
        list<vector<char>> *mdStamps    = in.readList(Reader<vector<char>>(&in));
        sealedMetaData                  = new SealedMetaData(metaData, mdStamps);
        operation                       = sealedMetaData;
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

void SmartStamp::initFields()
{
  if (!parseTried)
    parse();
}

unsigned char *SmartStamp::readSHA256(sdf_istream *in)
{
  auto *hash = new unsigned char[SHA256_DIGEST_LENGTH];
  in->readRaw(hash, SHA256_DIGEST_LENGTH);
  return hash;
}

json SmartStamp::toJson()
{
  json json;
  json["data"] = base64::encode(*data);
  return json;
}

vector<char> *SmartStamp::toRawData()
{
  return data;
}

unsigned char *SmartStamp::getDocHash()
{
  initFields();
  if (docHash == nullptr)
  {
    throw SmartStampError(__FILE__, __LINE__, "Missing docHash in SmartStamp.");
  }
  return docHash;
}

SmartStamp::VerificationResult *SmartStamp::verifyByContents(char *documentContents, char *optHashInBlockchain, bool provideInstructions)
{
  auto *vm = new OperationEvaluator();
  return verifyByHashHelper(vm, vm->hash(documentContents, SHA256_DIGEST_LENGTH), provideInstructions);
}

SmartStamp::VerificationResult *SmartStamp::verifyByHash(unsigned char *documentHash, char *optHashInBlockchain, bool provideInstructions)
{
  auto *vm = new OperationEvaluator();
  return verifyByHashHelper(vm, documentHash, provideInstructions);
}

SmartStamp::VerificationResult *SmartStamp::verifyByHashHelper(SmartStamp::OperationEvaluator *vm, unsigned char *documentHash, bool provideInstructions)
{
  initFields();
  return vm->verify(operations, documentHash, nullptr, provideInstructions);
}

unsigned char *SmartStamp::getRootHash() const
{
  return rootHash;
}

list<SmartStamp::Operation *> *SmartStamp::getOperations() const
{
  return operations;
}

SmartStamp::Blockchain *SmartStamp::getBlockchain() const
{
  return blockchain;
}

SmartStamp::DocumentInfo *SmartStamp::getDocumentInfo() const
{
  return documentInfo;
}

SmartStamp::SealedMetaData *SmartStamp::getSealedMetaData() const
{
  return sealedMetaData;
}

BundleMethod SmartStamp::getBundleMethod() const
{
  return bundleMethod;
}

void SmartStamp::BlockchainDescriptor::init(string &_blockchainGeneralName, string &_instanceName)
{
  blockchainGeneralName = new string(_blockchainGeneralName);
  instanceName          = new string(_instanceName);
}

SmartStamp::BlockchainDescriptor::BlockchainDescriptor(string &_blockchainGeneralName, string &_instanceName)
{
  init(_blockchainGeneralName, _instanceName);
}

//void SmartStamp::BlockchainDescriptor::write(sdf_ostream &out)
//{
//  out.write(blockchainGeneralName);
//  out.write(instanceName);
//}

SmartStamp::BlockchainDescriptor::BlockchainDescriptor(sdf_istream in)
{
  blockchainGeneralName = in.readString();
  instanceName=in.readString();
}

json SmartStamp::BlockchainDescriptor::toJson()
{
  json json;
  json["generalName"]  = *blockchainGeneralName;
  json["instanceName"] = *instanceName;
  return json;
}

SmartStamp::OperationEvaluator::OperationEvaluator()
{
  additionalInfo                  = new string();
  optInstructions                 = nullptr;
  origDocComparisonDone           = false;
  anchorComparisonDone            = false;
  verificationSources             = new list<VerificationSource>();
  digest                          = MessageDigest::getInstance("SHA-256");
  optUsrProvAnchorInBC            = nullptr;
  optLookedUpAnchorInBlockchain   = nullptr;
  optLookedUpVerificationSources  = nullptr;
}

SmartStamp::VerificationResult *SmartStamp::OperationEvaluator::verify( list<SmartStamp::Operation *> *operations,
                                                                        unsigned char *origDocHash,
                                                                        char *optoptBCAnchor,
                                                                        bool provideInstructions)
{
  memcpy(accu, origDocHash, SHA256_DIGEST_LENGTH);
  bool verified         = false;
  optUsrProvAnchorInBC  = optoptBCAnchor;
  origDocComparisonDone = false;
  anchorComparisonDone  = false;
  if (provideInstructions)
  {
    optInstructions = new string();
  }
  for (const Operation *operation: *operations)
  {
    operation->execute(*this);
  }
  if (origDocComparisonDone && anchorComparisonDone)
  {
    verified = true;
  }
  return new VerificationResult(verified, *verificationSources, *additionalInfo, optInstructions);
}

SmartStamp::OperationEvaluator::~OperationEvaluator()
{
  delete digest;
  delete optUsrProvAnchorInBC;
  delete optLookedUpAnchorInBlockchain;
  delete optLookedUpVerificationSources;
  delete additionalInfo;
  delete verificationSources;
  delete optInstructions;
}

json SmartStamp::VerificationSource::toJson()
{
  json j{{"name", sourceName}};
  if (optBlockChainDesc != nullptr)
  {
    json descJson = optBlockChainDesc->toJson();
    if (optBlockChainId != nullptr)
    {
      descJson["txId"] = *optBlockChainId;
    }
    j["blockchain"] = descJson;
  }
  return j;
}

SmartStamp::VerificationSource::VerificationSource(string &_sourceName)
{
  sourceName        = _sourceName;
  optBlockChainDesc = nullptr;
  optBlockChainId   = nullptr;
}

SmartStamp::VerificationSource::VerificationSource(string &_sourceName, BlockchainDescriptor *_blockChainDesc,
                                       string *_blockChainId)
{
  sourceName        = _sourceName;
  optBlockChainDesc = _blockChainDesc;
  optBlockChainId   = _blockChainId;
}

SmartStamp::VerificationResult::VerificationResult(bool _verified, list<VerificationSource> _verificationSources,
                                                   string _additionalInfo, string *_optInstructions)
{
  verified            = _verified;
  verificationSources = std::move(_verificationSources);
  additionalInfo      = std::move(_additionalInfo);
  optInstructions     = _optInstructions;
}

json SmartStamp::VerificationResult::toJson()
{
  json j{{"verified", verified}};
  json sources = json::array({});
  for (VerificationSource source: verificationSources)
  {
    json je = source.toJson();
    sources.push_back(je);
  }
  j["sources"]        = sources;
  j["additionalInfo"] = additionalInfo;
  if (optInstructions != nullptr)
  {
    j["instructions"] = *optInstructions;
  }
  return j;
}

void SmartStamp::Append::execute(OperationEvaluator &vm) const
{
  char combo[2*SHA256_DIGEST_LENGTH];
  memcpy(combo, vm.accu, SHA256_DIGEST_LENGTH);
  memcpy(combo+SHA256_DIGEST_LENGTH, hash, SHA256_DIGEST_LENGTH);
  memcpy(vm.accu, vm.hash(combo, 2*SHA256_DIGEST_LENGTH), SHA256_DIGEST_LENGTH);
  vm.instruct("Append " + to_hex(hash, SHA256_DIGEST_LENGTH) + " and hash it, resulting in " + to_hex(vm.accu, SHA256_DIGEST_LENGTH) + ".");
}

SmartStamp::Append::Append(unsigned char *_hash)
{
  memcpy(hash, _hash, SHA256_DIGEST_LENGTH);
}

//void SmartStamp::Append::write(sdf_ostream out)
//{
//  out.write(OPCODE_APPEND_THEN_SHA256);
//  SmartStamp::writeSHA256(out, hash);
//}

void SmartStamp::DocHash::execute(SmartStamp::OperationEvaluator &vm) const
{
  vm.instruct(
      "Check that hash in SmartStamp " + to_hex(vm.accu, SHA256_DIGEST_LENGTH) + " equals actual document hash " +
      to_hex(docHash, SHA256_DIGEST_LENGTH) + ".");
  if (memcmp(vm.accu, docHash, SHA256_DIGEST_LENGTH) != 0)
  {
    throw SmartStampError(__FILE__, __LINE__,
                          "Original document hash does not equal document hash contained in SmartStamp.");
  }
  vm.setOrigDocComparisonDone(true);
}

SmartStamp::Prepend::Prepend(unsigned char *_hash)
{
  memcpy(hash, _hash, SHA256_DIGEST_LENGTH);
}

void SmartStamp::Prepend::execute(SmartStamp::OperationEvaluator &vm) const
{
  char combo[2*SHA256_DIGEST_LENGTH];
  memcpy(combo, hash, SHA256_DIGEST_LENGTH);
  memcpy(combo+SHA256_DIGEST_LENGTH, vm.accu, SHA256_DIGEST_LENGTH);
  memcpy(vm.accu, vm.hash(combo, 2*SHA256_DIGEST_LENGTH), SHA256_DIGEST_LENGTH);
  vm.instruct("Prepend " + to_hex(hash, SHA256_DIGEST_LENGTH) + " and hash it, resulting in " + to_hex(vm.accu, SHA256_DIGEST_LENGTH) + ".");
}

SmartStamp::Anchor::Anchor(unsigned char *_hash)
{
  memcpy(hash, _hash, SHA256_DIGEST_LENGTH);
}

void SmartStamp::Anchor::execute(SmartStamp::OperationEvaluator &vm) const
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
    if (memcmp(vm.accu, vm.optUsrProvAnchorInBC, SHA256_DIGEST_LENGTH) != 0)
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
    if (memcmp(vm.accu, vm.optLookedUpAnchorInBlockchain, SHA256_DIGEST_LENGTH) != 0)
    {
      throw SmartStampError(__FILE__, __LINE__, "Calculated anchor does not equal looked up anchor in blockchain.");
    }
    if (vm.optLookedUpVerificationSources != nullptr) // paranoia
    {
      vm.verificationSourcesAddAll(vm.optLookedUpVerificationSources);
    }
  }
}

SmartStamp::Blockchain::Blockchain(SmartStamp::BlockchainDescriptor *_blockChainDesc, string _blockChainId,
                                   time_t _insertedIntoBlockchainAt)
{
  blockChainDesc            = _blockChainDesc;
  blockChainId              = std::move(_blockChainId);
  insertedIntoBlockchainAt  = _insertedIntoBlockchainAt;
}

SmartStamp::Blockchain::~Blockchain()
{
  delete blockChainDesc;
}

void SmartStamp::Blockchain::execute(SmartStamp::OperationEvaluator &vm) const
{
  string msg="Registered in blockchain "+blockChainDesc->toString()+" using TxId or Id "+blockChainId+" at "+format_time(insertedIntoBlockchainAt, "%H:%M:%ST%Y-%m-%d");
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

time_t SmartStamp::Blockchain::getInsertedIntoBlockchainAt() const
{
  return insertedIntoBlockchainAt;
}

SmartStamp::BlockchainDescriptor *SmartStamp::Blockchain::getBlockChainDesc() const
{
  return blockChainDesc;
}

const string &SmartStamp::Blockchain::getBlockChainId() const
{
  return blockChainId;
}

SmartStamp::DocumentInfo::DocumentInfo(string *_optLookupInfo, string *_optName, string *_optContentType)
{
  optLookupInfo   = _optLookupInfo;
  optName         = _optName;
  optContentType  = _optContentType;
}

SmartStamp::DocumentInfo::~DocumentInfo()
{
  delete optLookupInfo;
  delete optName;
  delete optContentType;
}

void SmartStamp::DocumentInfo::execute(SmartStamp::OperationEvaluator &vm) const
{
  string infoText;
  if (optLookupInfo != nullptr)
  {
    infoText.append("Document lookup info=" + *optLookupInfo + "\n");
  }
  if (optName != nullptr)
  {
    infoText.append("Document name=" + *optName + "\n");
  }
  if (optContentType != nullptr)
  {
    infoText.append("Document content type=" + *optContentType + "\n");
  }
  vm.additionalInfo->append(infoText);
  if (!infoText.empty())
  {
    vm.instruct(infoText);
  }
}

SmartStamp::SealedMetaData::SealedMetaData(string *_data, list<vector<char>> *_metaDataStamps)
{
  data            = _data;
  metaDataStamps  = _metaDataStamps;
}

SmartStamp::SealedMetaData::~SealedMetaData()
{
  delete data;
  delete metaDataStamps;
}

void SmartStamp::SealedMetaData::execute(SmartStamp::OperationEvaluator &vm) const
{
  string infoText;
  string str;
  for (const vector<char> &chVector:*metaDataStamps){
    str+= base64::encode( chVector )+'\n';
//    str+= to_hex((unsigned char*)&chVector[0], static_cast<int>(chVector.size()));
  }
  infoText.append("Sealed meta data: contents=(" + *data + "), meta data SmartStamps=(" + str + ")\n");
//    string infoText=info.toString();
  vm.additionalInfo->append(infoText);
  if (!infoText.empty())
  {
    vm.instruct(infoText);
  }
}

string *SmartStamp::SealedMetaData::getData() const
{
  return data;
}

list<vector<char>> *SmartStamp::SealedMetaData::getMetaDataStamps() const
{
  return metaDataStamps;
}

