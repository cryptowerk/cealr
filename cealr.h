//
// Created by Olaf Zumpe on 6/8/18.
//
#ifndef CEALR_H
#define CEALR_H
static const char *const CEALR = "cealr";

static const char *const DEFAULT_SERVER = "http://localhost:8080/platform";

static const int MAX_BUFFER_SIZE = 0x4000;

#include <string>
#include <exception>
#include <cstdlib>
#include "Properties.h"
//#include "JSON.h"
#include <nlohmann/json.hpp>
#include <set>
#include <regex>

// for convenience
using JSON = nlohmann::json;

using namespace std;

class PrintUsageMessage : public exception {
private:
    string *errMsg;
    string cmdName;
public:
    PrintUsageMessage(const string &);

    PrintUsageMessage();

    virtual const char *what();

    string getCmd();

    PrintUsageMessage(const string, string * );

    void usageMessage(string cmdName);

    virtual ~PrintUsageMessage() _NOEXCEPT;
};

class Cealr {
private:
    string cmdName;
    string *server;
    string *apiKey;
    string *apiCredential;
    string *email;
    bool verbose;
    bool registerArgFound;
    bool registerClient;
    bool seal;
    string hexHashes;
    string docNames;
    Properties *properties;

    void initFromPropIfNull(string **, const string);
    string *getStringMatching(const string &question, regex regexp);
    string *getOptString(const string &question);
    char getSingleCharacterAnswer(const string &question, const std::__1::set<char> validAnswers, const char defaultAnswer);
    string *getPassword(const string &question, int minLength, int minDigits, int minSmall, int minCaps);
    string *readPassword();
    string *hashFile(const string sFile);

public:
    Cealr(const int, const char**);
    virtual ~Cealr();
    void run();

    JSON registerUser(const string &firstname, const string &lastName, const string *organization) const;

    JSON creds(const string &password) const;

    void addToHashes(const string &filename);

    string *getEnvAsString(const string &) const;

    JSON sealFile() const;
    JSON verifySeal() const;
};

#endif //CEALR_H
