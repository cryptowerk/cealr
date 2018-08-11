/*
 * _____ _____  _____  ____   ______
 *|   __|   __|/  _  \|   |  |   _  |  Command line tool for sealing files with Cryptowerk API
 *|  |__|   __|   _   |   |__|
 *|_____|_____|__| |__|______|__|\__\  https://github.com/cryptowerk/cealr
 *
 *Licensed under the Apache 2.0 License <https://opensource.org/licenses/Apache-2.0>.
 *Copyright (c) 2018 Cryptowerk <http://www.cryptowerk.com>.
 *
 */

#include "cealr.h"
#include "CurlUtil.h"
#include "fileUtil.h"
#include "OpenPgpSign.h"
#include <openssl/sha.h>
#include <zconf.h>
#include <sys/termios.h>

string *Cealr::hashFile(const string sFile) {
    ifstream ifs(sFile.c_str(), ifstream::binary);
    string *hashHex = nullptr;
    if (ifs.is_open()) {
        SHA256_CTX sha256Ctx;
        SHA256_Init(&sha256Ctx);
        ifs.unsetf(ios::skipws);
        ifs.seekg(0, std::ios::end);
        auto size = (unsigned long)ifs.tellg();
        ifs.seekg(0, std::ios::beg);

        // reserve capacity
        unsigned long bufSize = (size < MAX_BUFFER_SIZE) ? size : MAX_BUFFER_SIZE;
        char buffer[bufSize];
        // read data
        unsigned long ptr = bufSize; // init with ptr after first read
        do {
            ifs.read(buffer, bufSize);
            SHA256_Update(&sha256Ctx, &buffer, bufSize);
            // since read does not return how many bytes are read, we have to keep track ourselves
            if ((ptr += bufSize)>size) {
                bufSize -= ptr-size;
                ptr = size;
            }
            // ifs.eof() is only true if we read beyond eof. We are keeping track of the remaining bytes to read and read
            // never more than available, so eof is never triggered and we have to exit based on bufSize==0
        } while(bufSize);
        ifs.close();
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_Final(hash, &sha256Ctx);
        hashHex = new string(toHex(hash, SHA256_DIGEST_LENGTH));
    } else {
        stringstream what;
        what << "Cannot open file '" << sFile << "'.";
        string sWhat = what.str();
        throw PrintUsageMessage(cmdName, new string(sWhat));
    }
    return hashHex;
}

string Cealr::toHex(const unsigned char *hash, const int size ) {
    stringstream buf;
    for(int i = 0; i < size; i++) {
        buf << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return buf.str();
}

void PrintUsageMessage::usageMessage(string cmdName) {
    const char *sampleServerUrl = "https://devapi1.cryptowerk.com/platform";

    cout << "Proof that file has not changed since registration:" << endl;
    cout << cmdName << " [options] <file>" << endl;
    cout << endl;
    cout << "Usage for sealing own files:" << endl;
    cout << cmdName << " [options] --seal <file>" << endl;
//    cout << cmdName << " [options] --sign <file>" << endl;
    cout << endl;
    cout << "  General options:" << endl;
    cout << "  --verbose         enable verbose output" << endl;
    cout << "  --server          server URL, e.g. '" << sampleServerUrl << "'" << endl;
    cout << endl;
    cout << "  Mode of operation, one of:" << endl;
    cout << "  --help            this help" << endl;
    cout << "  --register        to register a free account with CryptoWerk and store account credentials in " << DEFAULT_PROPERTIES  << endl;
    cout << "  --seal [filename] register a document in blockchain(s)" << endl;
    cout << endl;
    cout << "Additional options with --seal:" << endl;
    cout << "  --update          Email update when submitted file is verifiable in blockchain" << endl;
    cout << "  --apiKey          API key, e.g. '" << "TskZZ8Zc2QzE3G+lxvUnWPKMk27Ucd1tm9K/YSPXWww=" << "'" << endl;
    cout << "  --apiCredential   API credential, e.g. ' " << "vV/2buaDD5aAcCQxCtk4WRJs/yK+BewThR1qUXikdJo=" << "'" << endl;
    cout << "  --login           to re-use an already registered account with CryptoWerk (or simply get the file " << DEFAULT_PROPERTIES << " from a system where you previously registered your account" << endl;
    cout << endl;
    cout << "Example for sealing:" << endl;
    cout << "  echo 'Hello, world.' >hello.txt" << endl;
    cout << "  " << cmdName << " --seal hello.txt" << endl;
    cout << endl;
    cout << "Example verify a file" << endl;
    cout << "  " << cmdName << " hello.txt" << endl;

}

char Cealr::getSingleCharacterAnswer(const string &question, const set<char> validAnswers, const char defaultAnswer) {
    int c;
    bool ok;
    do {
        cout << question;
        cin.clear();
        string input;
        if (isatty(fileno(stdin))) {
            static struct termios currentTerminal, singleCharTerminal;
            tcgetattr(STDIN_FILENO, &currentTerminal);
            singleCharTerminal = currentTerminal;
            singleCharTerminal.c_lflag &= ~(ICANON);
            tcsetattr(STDIN_FILENO, TCSANOW, &singleCharTerminal);
            c = getchar();
            fflush(stdout);
            tcsetattr(STDIN_FILENO, TCSANOW, &currentTerminal);
        } else {
            getline(cin, input);
            c = input[0];
        }

        c = toupper(c);
        if (c == '\n' || c == 0) {
            c = defaultAnswer;
        } else {
            cout << endl;
        }
        if (!(ok = (bool) validAnswers.count((char) c))) {
            cout << "Invalid answer, please try again" << endl;
        }
    } while (!ok);
    return (char) c;
}

string *Cealr::getStringMatching(const string &question, regex regexp) {
    bool ok;
    string input;
    do {
        cout << question;
        cin.clear();
        getline(cin, input);
        input = Properties::trim(input);
        smatch m;
        ok = regex_match(input, m, regexp);
        if (!ok) {
            cout << "Invalid answer, please try again" << endl;
        }
    } while (!ok);
    return new string(input);
}

string *Cealr::getPassword(const string &question, int minLength, int minDigits, int minSmall, int minCaps) {
    bool ok = false;
    string input;
    do {
        if (isatty(fileno(stdin))) {
            cin.clear();
            input = getpass(question.c_str());
        } else {
            cerr << "Password input is only possible when cealr is started in interactive mode." << endl
                 << "Currently the standard input is not a console." << endl
                 << "Please use one of the options below to enter your password:" << endl
                 << " - start cealr directly in a the command line in a console" << endl
                 << " - set the environment variable CEALR_PASSWORD" << endl
                 << " - add line password=<your password>" << endl
                 << "   in the file \"" << properties->getFile() << "" << endl;
            exit(1);
        }
        unsigned long length = input.length();
        if (length < minLength) {
            cout << "The password is not long enough: " << endl;
        } else {
            int digits, small, caps;
            digits = small = caps = 0;
            for (unsigned long i = 0; i < length; i++) {
                char c = input[i];
                if (c >= '0' && c <= '9') {
                    digits++;
                }
                if (isupper(c)) {
                    small++;
                }
                if (isupper(c)) {
                    caps++;
                }
            }
            if (digits < minDigits) {
                cout << "The needs at least " << minDigits << " digits." << endl;
            } else if (small < minSmall) {
                cout << "The needs at least " << minSmall << " small letters." << endl;
            } else if (caps < minCaps) {
                cout << "The needs at least " << minCaps << " capital letters." << endl;
            } else {
                ok = true;
            }
        }
    } while (!ok);
    return new string(input);
}

string *Cealr::getOptString(const string &question) {
    string input;
    cout << question;
    cin.clear();
    getline(cin, input);
    input = Properties::trim(input);
    return (input[0]) == 0 ? nullptr : new string(input);
}

Cealr::Cealr(const int argc, const char **argv) {
#ifndef NDEBUG
    //todo oz: Only for testing/debugging
    if (isatty(fileno(stdin))) {
        getSingleCharacterAnswer("Attach debugger?", {'Y', 'N'}, 'N');
    }
#endif
    cmdName = argc > 0 ? argv[0] : CEALR;
    verbose = false;

    properties = new Properties();
    cout << *properties << endl;

    // should call default constructor
    registerArgFound = false;
    registerClient   = false;
    seal             = false;
    sign             = false;
    server           = nullptr;
    email            = nullptr;
    apiKey           = nullptr;
    apiCredential    = nullptr;

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        bool hasMoreArgs = i + 1 < argc;
        bool callAddToHashes = false;
        if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--register" || arg == "--login") {
            registerClient = arg == "--register";
            registerArgFound = true;
        } else if (i + 1 < argc && arg == "--seal") {
            seal = true;
            callAddToHashes = true;
            arg = argv[++i];
        } else if (i + 1 < argc && arg == "--sign") {
            seal = true;
            sign = true;
            callAddToHashes = true;
            arg = argv[++i];
        } else if (hasMoreArgs && arg == "--server") {
            server = new string(argv[++i]);
        } else if (hasMoreArgs && arg == "--apiKey") {
            apiKey = new string(argv[++i]);
        } else if (hasMoreArgs && arg == "--apiCredential") {
            apiCredential = new string(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            throw PrintUsageMessage(cmdName);
        } else {
            callAddToHashes = true;
        }
        if (callAddToHashes) {
            addToHashes(arg);
        }
    }
    if (apiKey && !apiCredential) {
        stringstream what;
        what << "The option --apiKey requires also the option --apiCredential." << endl
             << "You can use the option --apiCredential on its own if an apiKey" << endl
             << "is provided in properties or in environment variable \"CEALR_APIKEY\"" << endl
             << "to override the environment variable \"CEALR_APICREDENTIAL\"" << endl;

        throw PrintUsageMessage(cmdName, new string(what.str()));
    }
    if (!apiKey){
        apiKey = getEnvAsString("CEALR_APIKEY");
    }
    if (!apiCredential){
        apiCredential = getEnvAsString("CEALR_APICREDENTIAL");
    }
}

void Cealr::addToHashes(const string &fileName) {
    string *hashHex = hashFile(fileName);
    if (!hexHashes.empty()) {
        hexHashes.append(",");
    }
    hexHashes.append(*hashHex);
    fileNames.push_back(fileName);
    string *docName = fileNameWithoutPath(fileName);
    if (!docNames.empty()) {
        docNames.append(",");
    }
    docNames.append(*docName);
}

void Cealr::run() {
    if (!server) {
        if ((*properties)["server"].empty()) {
            server      = getEnvAsString("CEALR_SERVER");
            if (!server){
                server  = new string(DEFAULT_SERVER);
            }
        } else {
            server      = new string((*properties)["server"]);
        }
    }
    //in case of option --seal
    if (registerArgFound || (seal && !apiKey && (*properties)["apiKey"].empty() && (*properties)["email"].empty())) {
        // ask if seal without apiKey
        if (!registerArgFound) {
            registerClient = getSingleCharacterAnswer("Are you already registered with Cryptowerk? [y/N]: ", {'Y', 'N'}, 'N') == 'N';
        }
        regex email_pattern("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", regex_constants::icase);
        if (email && !regex_match(*email, email_pattern)) {
            cout << "The parameter \"--email " << email << "\" was not accepted as a valid email address." << endl;
            email = nullptr;
        }
        //in case of registration ask for email, password, first name, last name and optional for org
        //todo oz: email = new string("olaf.zumpe@gmail.com");
        if (!email) {
            email = getStringMatching("Please enter your email address..................: ", email_pattern);
        }
        if (registerClient) {
            //in case of registration ask for email, password, first name, last name and optional for org
            string firstName, lastName;
            regex name_pattern = regex("^[[:alpha:] \\-]+$");
            firstName = /*"Olaf";//todo oz:*/ *getStringMatching("Please enter your first name.....................: ", name_pattern);
            lastName  = /*"Zumpe"; //todo oz:*/ *getStringMatching("Please enter your last name......................: ", name_pattern);
            string *organization = /*NULL; //todo oz:*/ getOptString("Please enter your organization (if applicable)...: ");
            cout  << endl << "Contacting server for user registration\""  << *server << "\"" << endl << endl;
            // register user
            JSON returnJson = registerUser(firstName, lastName, organization);
//            JSON returnJson = JSON::parse("{\"maxSupportedAPIVersion\":5,\"success\":true,\"minSupportedAPIVersion\":1}");
            properties->erase("apiKey");
            // safe data on properties
            // inform about email confirmation
            cout << "You are now registered with our server \""  << *server << "\"."<< endl
                 << "An email has been sent to your account \"" << *email << "\"." << endl
                 << "Please follow the instructions in this email to choose your password and" << endl
                 << "to activate your account." << endl
                 << "After account activation you will be able to use the cealr command line tool to " << endl
                 << "seal files for proof of existence." << endl
                 << endl;
        }
        (*properties)["email"]          = *email;
        if (*server!=DEFAULT_SERVER) {
            (*properties)["server"]     = *server;
        }
        properties->erase("apiKey");
        properties->erase("apiCredential");
        properties->save();
        // todo No need to exit here, if user just has been created we could wait in cealr (password entry) for activation
        // todo or we exit here and they just need to start cealr again after activation
        if (registerClient){
            exit(1);
        }
    }
    if (seal) {
        initFromPropIfNull(&apiKey, "apiKey");
        initFromPropIfNull(&apiCredential, "apiCredential");
        initFromPropIfNull(&email, "email");
        initFromPropIfNull(&server, "server");
        if (!apiKey || !apiKey->length() || !apiCredential || !apiCredential->length()) {
            string *password = readPassword();
            cout  << endl << "Contacting server \""  << *server << "\" to retrieve your account credentials." << endl << endl;
            JSON returnJson  = creds(*password);
            cout << returnJson.dump() << endl;
            string str       = returnJson["apiKey"];
            apiKey           = new string(str);
            str              = returnJson["apiCredential"];
            apiCredential    = new string(str);
            if (!apiCredential || !apiCredential->length()) {
                cerr << "The apiCredential has already been revealed for this apiKey." << endl
                     << "For your security we can show an apiCredential exactly one time." << endl
                     << "The command line tool is usually storing it in ~/.cealr/config.properties." << endl
                     << "If you have another system or user where you use the same CryptoWerk account" << endl
                     << "you can copy the file ~/.cealr/config.properties from there and replace the" << endl
                     << "same file on this system/for this user." << endl << endl
                     << "Alternatively you could login to your CryptoWerk Portal and generate a new API key." << endl
                     << "Be careful: This would invalidate the current API key for this account-user" << endl
                     << "combination which may be used in other systems." << endl;
                exit(1);
            }
            (*properties)["apiKey"] = *apiKey;
            (*properties)["apiCredential"] = *apiCredential;
            properties->save();
        }
    }
    if (hexHashes.empty()) {
        throw PrintUsageMessage(cmdName, new string("Missing mode of operation. You might want to try option '--help'."));
    }
    if (seal) {
        if (sign) {
            OpenPgpSign openPgpSign(GPGME_SIG_MODE_DETACH);
            for (const string &fileName:fileNames) {
                signature = openPgpSign.sign(fileName);
                if (verbose) {
                    cout << "Signature: " << fileName << endl << signature << endl;
                }
            }
        }
        cout  << endl << "Contacting server \""  << *server << "\" to seal your file \"" << docNames << "\""  << endl << endl;
        sealFile();
        cout << "File \"" << docNames << "\" is successfully registered with Cryptowerk." << endl;
    } else {
        const JSON &returnJson = verifySeal();
        auto docs = returnJson["documents"];
        if (docs!=NULL) {
            int foundDocs = docs.size();
            if (foundDocs) {
                cout << "A file with the same hash as \"" << docNames << " has been registered with Cryptowerk " << foundDocs << " time(s)." << endl;
                cout << "Details:" << endl;
                // todo print out details for the document (what blockchain(s) / transaction(s) / time registered)
                for (auto &doc : docs) {
                    string docName = doc["name"];
                    cout << "Submitted at " << formatTime(doc["submittedAt"], "%H:%M:%ST%Y-%m-%d");
                    if (docName.empty()) {
                        cout << " without name";
                    } else {
                        cout << " as " << docName;
                    }
                    cout << endl;
                    auto bcRegs = doc["blockchainRegistrations"];
                    if (bcRegs!=NULL){
                        for (auto bcReg:bcRegs) {
                            auto bcDesc = bcReg["blockChainDesc"];
                            auto bc = bcDesc["generalName"];
                            auto instance = bcDesc["instanceName"];
                            cout << " put into blockchain: " << bc << ":" << instance << " at " << formatTime(bcReg["insertedIntoBlockchainAt"], "%H:%M:%ST%Y-%m-%d") << ", Transaction ID: " << bcReg["blockChainId"] << endl;
                        }
                    } else {
                        cout << endl << "There was no blockchain registration for this file." << endl;
                    }
                }
            } else {
                cout << endl << "This file has not been registered with Cryptowerk." << endl;
            }
        } else {
            cerr << "unexpected answer from server: \"" << returnJson.dump() << "\"" << endl;
        }
    }
}

string Cealr::formatTime(const time_t timestamp, const string format) {
    struct tm *time;
    char szTime[40];
    const time_t epoch = timestamp/1000;
    time = localtime(&epoch);
    strftime(szTime, sizeof(szTime), format.c_str(), time);
    return string(szTime);
}

JSON Cealr::sealFile() const {
    JSON json;
    json["name"]                = docNames;
    json["contentType"]         = *new string("application/octet-stream");
    json["store"]               = true; //
    json["hashes"]              = hexHashes;
    json["publiclyRetrievable"] = true;

    stringstream url;
    url << *server << "/API/v5/register";
    string sUrl                 = url.str();
    CurlUtil curlUtil(sUrl, verbose);
    stringstream apiCredStr;
    apiCredStr << "X-ApiKey: " << *apiKey << " " << *apiCredential;
    const string apiCreds = apiCredStr.str();
    curlUtil.addHeader(apiCreds);
    string *returnData          = curlUtil.post(json);
//    string *returnData = new string("{\"maxSupportedAPIVersion\":5,\"success\":true,\"minSupportedAPIVersion\":1}");
    auto returnJson             = JSON::parse(*returnData);

    return returnJson;
}

JSON Cealr::verifySeal() const {
    JSON json;
    json["name"]             = docNames;
    json["contentType"]      = *new string("application/octet-stream");
    json["retrievalDocHash"] = hexHashes;
    stringstream url;
    url << *server << "/API/v5/verify";
    string sUrl = url.str();
    CurlUtil curlUtil(sUrl, verbose);
    curlUtil.addHeader("X-ApiKey: TskZZ8Zc2QzE3G/lxvUnWPKMk27Ucd1tm9K+YSPXWww= vV+2buaDD5aAcCQxCtk4WRJs+yK/BewThR1qUXikdJo=");
    string *returnData = curlUtil.post(json);
//    string *returnData = new string("{\"maxSupportedAPIVersion\":5,\"success\":true,\"minSupportedAPIVersion\":1}");
    auto returnJson = JSON::parse(*returnData);

    return returnJson;
}

JSON Cealr::registerUser(const string &firstName, const string &lastName, const string *organization) const {
    JSON json;
    json["email"]               = *email;
    json["testAccountName"]     = *email;
    json["optFirstName"]        = firstName;
    json["optLastName"]         = lastName;
    if (organization) {
        json["optOrganization"] = *organization;
    }
    stringstream url;
    url << *server << "/API/v5/registerUser";
    string sUrl                 = url.str();
    CurlUtil curlUtil(sUrl, verbose);
    string *returnData          = curlUtil.post(json);
    auto returnJson = JSON::parse(*returnData);

    return returnJson;
}

JSON Cealr::creds(const string &password) const {
    JSON json;
    json["email"]      = *email;
    json["password"]   = password;
    stringstream url;
    url << *server << "/API/v5/creds";
    string sUrl        = url.str();
    CurlUtil curlUtil(sUrl, verbose);
    string *returnData = curlUtil.post(json); // {"maxSupportedAPIVersion":5,"success":true,"minSupportedAPIVersion":1}
    cout << returnData;
    auto returnJson    = JSON::parse(*returnData);

    return returnJson;
}

string *Cealr::readPassword() {
    string *password = nullptr;
    initFromPropIfNull(&password, "password");
    if (!password) {
        password = getEnvAsString("CEALR_PASSWORD");
        if (!password) {
            stringstream question;
            question << "Please enter the password for your Cryptowerk account \"" << *email << "\" ";
            password = getPassword(question.str(), 8, 0, 0, 0);
        }
    }

    return password;
}

string *Cealr::getEnvAsString(const string &envKey) const {
    string *envStr = nullptr;
    char *envPwd = getenv(envKey.c_str());
    if (envPwd) {
        envStr = new string(envPwd);
    }
    return envStr;
}

void Cealr::initFromPropIfNull(string **pString, const string key) {
    if (*pString == nullptr && properties->count(key)) {
        *pString = new string((*properties)[key]);
    }
}

Cealr::~Cealr() {
    if (server) {
        delete server;
        server = nullptr;
    }
    if (apiKey) {
        delete apiKey;
        apiKey = nullptr;
    }
    if (apiCredential) {
        delete apiCredential;
        apiCredential = nullptr;
    }
    if (email) {
        delete email;
        email = nullptr;
    }
    if (properties) {
        delete properties;
        properties = nullptr;
    }

}

PrintUsageMessage::PrintUsageMessage(const string &command) : errMsg("") {
    cmdName = command;
}

const char *PrintUsageMessage::what() {
    return errMsg.what();
}

string PrintUsageMessage::getCmd() {
    return cmdName;
}

PrintUsageMessage::PrintUsageMessage(const string command, string *error) : errMsg(error->c_str()) {
    cmdName = command;
}

PrintUsageMessage::PrintUsageMessage() : errMsg("") {
    cmdName = "cealr";
}

//  --server https://devapi1.cryptowerk.com/platform --apiKey TskZZ8Zc2QzE3G/lxvUnWPKMk27Ucd1tm9K+YSPXWww= --api8888Credential vV+2buaDD5aAcCQxCtk4WRJs+yK/BewThR1qUXikdJo=
int main(int argc, const char **argv) {
    try {
        Cealr cealr(argc, argv);
        cealr.run();
    } catch (PrintUsageMessage &e) {
        int exitVal = 0;
        if (*e.what()) {
            string errorMsg(e.what());
            cerr << errorMsg << endl;
            exitVal = 1;
        }
        e.usageMessage(e.getCmd());
        return exitVal;
    }
    catch (PgpSignException &e){
        cerr << e.what();
        exit(1);
    }
    catch (FileException &e){
        cerr << e.what();
        exit(1);
    }
}

