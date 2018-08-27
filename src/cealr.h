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

#ifndef CEALR_H
#define CEALR_H
static const char *const CEALR = "cealr";

#ifdef NDEBUG
static const char *const DEFAULT_SERVER = "https://devapi1.cryptowerk.com/platform";
#else
static const char *const DEFAULT_SERVER = "http://localhost:8080/platform";
#endif // if CMAKE_BUILD_TYPE==DEBUG

static const int MAX_BUFFER_SIZE = 0x4000;

#include <string>
#include <exception>
#include <cstdlib>
#include "Properties.h"
#include "OpenPgpSign.h"
#include <nlohmann/json.hpp>
#include <set>
#include <regex>

using JSON = nlohmann::json;

using namespace std;

class PrintUsageMessage : public exception {
private:
    runtime_error errMsg;
    string cmdName;
public:
    explicit PrintUsageMessage(const string &);
    PrintUsageMessage(string, string * );
    PrintUsageMessage();
    virtual const char *what();
    string getCmd();
    void usageMessage(string cmdName);
//    ~PrintUsageMessage()/* _NOEXCEPT override*/;
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
    bool sign;
    vector<string> fileNames;
    string hexHashes;
    string docNames;
    Properties *properties;
    void initFromPropIfNull(string **, string);
    string *getStringMatching(const string &question, regex regexp);
    string *getOptString(const string &question);
    char getSingleCharacterAnswer(const string &question, set<char> validAnswers, char defaultAnswer);
    string *getPassword(const string &question, int minLength, int minDigits, int minSmall, int minCaps);
    string *readPassword();
    string *hashFile(string sFile);
    string toHex(const unsigned char *hash, int size );
    void addToHashes(const string &fileName, const string *version);

public:
    Cealr(int, const char**);
    virtual ~Cealr();
    void run();

    JSON registerUser(const string &firstName, const string &lastName, const string *organization) const;

    JSON creds(const string &password) const;

    string *getEnvAsString(const string &) const;

    JSON sealFile(const OpenPgpSign *openPgpSign = nullptr) const;
    JSON verifySeal() const;

    string formatTime(time_t timestamp, string format);
};

#endif //CEALR_H
