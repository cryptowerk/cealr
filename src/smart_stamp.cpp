#include <utility>

//
// Created by Olaf Zumpe on 9/5/18.
//

#include "smart_stamp.h"

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
  additionalInfo = new string();
  optInstructions = nullptr;
  origDocComparisonDone = false;
  anchorComparisonDone = false;
  verificationSources = new list<VerificationSource>();
  digest = MessageDigest::getInstance("SHA-256");
  optUsrProvAnchorInBC = nullptr;
  optLookedUpAnchorInBlockchain = nullptr;
  optLookedUpVerificationSources = nullptr;
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
  j["sources"] = sources;
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

//void SmartStamp::Append::write(sdf_ostream out)
//{
//  out.write(OPCODE_APPEND_THEN_SHA256);
//  SmartStamp::writeSHA256(out, hash);
//}
