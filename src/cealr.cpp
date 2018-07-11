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
#include <openssl/sha.h>
#include <zconf.h>
#include <sys/termios.h>

using namespace std;


string toHex(const unsigned char hash[SHA256_DIGEST_LENGTH]) {
    stringstream buf;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        buf << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return buf.str();
}

string *Cealr::hashFile(const string sFile) {
    ifstream ifs(sFile.c_str(), ifstream::binary);
    string *hashHex = NULL;
    if (ifs.is_open()) {
        SHA256_CTX sha256Ctx;
        SHA256_Init(&sha256Ctx);
        ifs.unsetf(ios::skipws);
        ifs.seekg(0, std::ios::end);
        unsigned long size = (unsigned long)ifs.tellg();
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
        hashHex = new string(toHex(hash));
    } else {
        stringstream what;
        what << "Cannot open file '" << sFile << "'.";
        string sWhat = what.str();
        throw PrintUsageMessage(cmdName, new string(sWhat));
    }
    return hashHex;
}

void PrintUsageMessage::usageMessage(string cmdName) {
    const char *sampleServerUrl = "https://devapi1.cryptowerk.com/platform";
    const char *sampleApiKey = "TskZZ8Zc2QzE3G/lxvUnWPKMk27Ucd1tm9K+YSPXWww=";
    const char *sampleApiCredential = "vV+2buaDD5aAcCQxCtk4WRJs+yK/BewThR1qUXikdJo=";

    cout << "Proof that file has not changed since registration:" << endl;
    cout << cmdName << " [options] <file>" << endl;
    cout << endl;
    cout << "Usage for sealing own files:" << endl;
    cout << cmdName << " [options] --seal <file>" << endl;
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
    cout << "  --apiKey          API key, e.g. '" << sampleApiKey << "'" << endl;
    cout << "  --apiCredential   API credential, e.g. ' " << sampleApiCredential << "'" << endl;
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
        string input = "";
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
        }
        if (!(ok = (bool) validAnswers.count((char) c))) {
            cout << "Invalid answer, please try again" << endl;
        }
    } while (!ok);
    return (char) c;
}

string *Cealr::getStringMatching(const string &question, regex regexp) {
    bool ok;
    string input("");
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
    string input("");
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
    string input = "";
    cout << question;
    cin.clear();
    getline(cin, input);
    input = Properties::trim(input);
    return (input[0]) == 0 ? NULL : new string(input);
}

Cealr::Cealr(const int argc, const char **argv) {
    cmdName = argc > 0 ? argv[0] : CEALR;
    verbose = false;

    properties = new Properties();
    cout << *properties << endl;

    // should call default constructor
    registerArgFound = false;
    registerClient = false;
    seal = false;
    server = NULL;
    email = NULL;
    apiKey = NULL;
    apiCredential = NULL;

    for (int i = 1; i < argc; i++) {
        const string arg = argv[i];
        bool hasMoreArgs = i + 1 < argc;
        if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--register" || arg == "--login") {
            registerClient = arg == "--register";
            registerArgFound = true;
        } else if (i + 1 < argc && arg == "--seal") {
            seal = true;
            addToHashes(argv[++i]);
        } else if (hasMoreArgs && arg == "--server") {
            server = new string(argv[++i]);
        } else if (hasMoreArgs && arg == "--apiKey") {
            apiKey = new string(argv[++i]);
        } else if (hasMoreArgs && arg == "--apiCredential") {
            apiCredential = new string(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            throw PrintUsageMessage(cmdName);
        } else {
            addToHashes(arg);
        }
    }
    if (apiKey && !apiCredential) {
        stringstream what("The option --apiKey requires also the option --apiCredential.\n");
        what << "You can use the option --apiCredential on its own if an apiKey\n"
             << "is provided in properties or in environment variable \"CEALR_APIKEY\"\n"
             << "to override the environment variable \"CEALR_APICREDENTIAL\"";

        throw PrintUsageMessage(cmdName, new string(what.str()));
    }
    if (!apiKey){
        apiKey = getEnvAsString("CEALR_APIKEY");
    }
    if (!apiCredential){
        apiCredential = getEnvAsString("CEALR_APICREDENTIAL");
    }
}

void Cealr::addToHashes(const string &filename) {
    string *hashHex = hashFile(filename);
    if (hexHashes.size() > 0) {
        hexHashes.append(",");
    }
    hexHashes.append(*hashHex);
}

void Cealr::run() {
    if (!server) {
        if (!(*properties)["server"].size()) {
            server = getEnvAsString("CEALR_SERVER");
            if (!server){
                server = new string(DEFAULT_SERVER);
            }
        } else {
            server = new string((*properties)["server"]);
        }
    }
    //in case of option --seal
    if (registerArgFound || (seal && !apiKey && !(*properties)["apiKey"].size() && !(*properties)["email"].size())) {
        // ask if seal without apiKey
        if (!registerArgFound) {
            registerClient = getSingleCharacterAnswer("Are you already registered with cryptowerk? [y/N]: ", {'Y', 'N'}, 'N') == 'N';
        }
        regex email_pattern("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", regex_constants::icase);
        if (email && !regex_match(*email, email_pattern)) {
            cout << "The parameter \"--email " << email << "\" was not accepted as a valid email address." << endl;
            email = NULL;
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
            // register user
            JSON returnJson = registerUser(firstName, lastName, organization);
            cout << "returnJson[\"success\"]" << returnJson["success"] << endl;
            (*properties)["email"]          = *email;
            properties->erase("apiKey");
            // todo dont save server, when it is the default server
            if (*server!=DEFAULT_SERVER) {
                (*properties)["server"]     = *server;
            }
            properties->save(); // exception???
            // safe data on properties
            // inform about email confirmation
            cout << "You are now registered with our server.\""  << *server << "\""<< endl
                 << "An email got send to your account \"" << *email << "." << endl
                 << "Please find it and follow the instructions in this email to choose your password and" << endl
                 << "to activate your account." << endl
                 << "After account activation you will be able to use the cealr command line tool to " << endl
                 << "seal files for proof of existence." << endl
                 << endl;
        }
        (*properties)["email"]          = *email;
        (*properties)["server"]         = *server;
        properties->save();
        // todo We could exit here, if user just got created and let them just start cealr again after activation
        // todo or we wait for activation inside cealr
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
            JSON returnJson = creds(*password);
            *apiKey = returnJson["apiKey"];
            *apiCredential = returnJson["apiCredential"];
            if (!apiCredential || !apiCredential->length()) {
                cerr << "The apiCredential has already been revealed for this apiKey. For your security we can show an apiCredential exactly one time. The command line tool is usually storing it in ~/.cealr/config.properties.";
                cerr << "If you have another system or user where you use the same CryptoWerk account you can copy the file ~/.cealr/config.properties from there and replace the same file on this system/for this user.";
                cerr << "Alternatively you could login to your CryptoWerk Portal and generate a new API key. Be careful: This would invalidate the current API key for this account-user combination which may be used in other systems.";
                exit(1);
            }
            (*properties)["apiKey"] = *apiKey;
            (*properties)["apiCredential"] = *apiCredential;
            properties->save();
        }
    }
    if (hexHashes.size()==0) {
        throw PrintUsageMessage(cmdName, new string("Missing mode of operation. You might want to try option '--help'."));
    }
    if (seal) {
        sealFile();
    } else {
        verifySeal();
    }
}

JSON Cealr::sealFile() const {
    JSON json;
    json["name"] = docNames;
    json["contentType"] = *new string("applicaton/octet-stream");
    json["store"] = true; //
    json["hashes"] = hexHashes; //

    stringstream url;
    url << *server << "/API/v5/register";
    string sUrl = url.str();
    CurlUtil curlUtil(sUrl, verbose);
    stringstream apiCredStr;
    apiCredStr << "X-ApiKey: " << *apiKey << " " << *apiCredential;
    const string apiCreds = apiCredStr.str();
    curlUtil.addHeader(apiCreds);
    string *returnData = curlUtil.post(json); // {"maxSupportedAPIVersion":5,"success":true,"minSupportedAPIVersion":1}
//    string *returnData = new string("{\"maxSupportedAPIVersion\":5,\"success\":true,\"minSupportedAPIVersion\":1}");
    auto returnJson = JSON::parse(*returnData);

    return returnJson;
}

JSON Cealr::verifySeal() const {
    JSON json;
    json["name"] = docNames;
    json["contentType"] = *new string("applicaton/octet-stream");
    json["hashes"] = hexHashes; //

    stringstream url;
    url << *server << "/API/v5/verify";
    string sUrl = url.str();
    CurlUtil curlUtil(sUrl, verbose);
    string *returnData = curlUtil.post(json); // {"maxSupportedAPIVersion":5,"success":true,"minSupportedAPIVersion":1}
//    string *returnData = new string("{\"maxSupportedAPIVersion\":5,\"success\":true,\"minSupportedAPIVersion\":1}");
    auto returnJson = JSON::parse(*returnData);

    return returnJson;
}

JSON Cealr::registerUser(const string &firstName, const string &lastName, const string *organization) const {
    JSON json;
    json["email"] = *email;
    json["testAccountName"] = *email;
    json["optFirstName"] = firstName;
    json["optLastName"] = lastName;
    if (organization) {
        json["optOrganization"] = *organization;
    }
    stringstream url;
    url << *server << "/API/v5/registerUser";
    string sUrl = url.str();
    CurlUtil curlUtil(sUrl, verbose);
    string *returnData = curlUtil.post(json); // {"maxSupportedAPIVersion":5,"success":true,"minSupportedAPIVersion":1}
//    string *returnData = new string("{\"maxSupportedAPIVersion\":5,\"success\":true,\"minSupportedAPIVersion\":1}");
    auto returnJson = JSON::parse(*returnData);

    return returnJson;
}

JSON Cealr::creds(const string &password) const {
    JSON json;
    json["email"] = *email;
    json["password"] = password;
    stringstream url;
    url << *server << "/API/v5/creds";
    string sUrl = url.str();
    CurlUtil curlUtil(sUrl, verbose);
    string *returnData = curlUtil.post(json); // {"maxSupportedAPIVersion":5,"success":true,"minSupportedAPIVersion":1}
//    string *returnData = new string("{\"maxSupportedAPIVersion\":5,\"success\":true,\"minSupportedAPIVersion\":1}");
    cout << returnData;
    auto returnJson = JSON::parse(*returnData);

    return returnJson;
}

string *Cealr::readPassword() {
    string *password = NULL;
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
    string *envStr = NULL;
    char *envPwd = getenv(envKey.c_str());
    if (envPwd) {
        envStr = new string(envPwd);
    }
    return envStr;
}

void Cealr::initFromPropIfNull(string **pString, const string key) {
    if (*pString == NULL && properties->count(key)) {
        *pString = new string((*properties)[key]);
    }
}

Cealr::~Cealr() {
    if (server) {
        delete server;
        server = NULL;
    }
    if (apiKey) {
        delete apiKey;
        apiKey = NULL;
    }
    if (apiCredential) {
        delete apiCredential;
        apiCredential = NULL;
    }
    if (email) {
        delete email;
        email = NULL;
    }
    if (properties) {
        delete properties;
        properties = NULL;
    }

}

PrintUsageMessage::PrintUsageMessage(const string &command) {
    cmdName = command;
    errMsg = (string *) NULL;
}

const char *PrintUsageMessage::what() {
    if (errMsg) {
        return errMsg->c_str();
    }
    return NULL;
}

string PrintUsageMessage::getCmd() {
    return cmdName;
}

PrintUsageMessage::PrintUsageMessage(const string command, string *error) {
    cmdName = command;
    errMsg = error;
}

PrintUsageMessage::~PrintUsageMessage() _NOEXCEPT {
    if (errMsg != NULL) {
        delete errMsg;
        errMsg = NULL;
    }
}

PrintUsageMessage::PrintUsageMessage() {
    cmdName = "cealr";
    errMsg = NULL;
}

//  --server https://devapi1.cryptowerk.com/platform --apiKey TskZZ8Zc2QzE3G/lxvUnWPKMk27Ucd1tm9K+YSPXWww= --api8888Credential vV+2buaDD5aAcCQxCtk4WRJs+yK/BewThR1qUXikdJo=
int main(int argc, const char **argv) {
    try {
        Cealr cealr(argc, argv);
        cealr.run();
    } catch (PrintUsageMessage &e) {
        int exitVal = 0;
        if (e.what()) {
            string errorMsg(e.what());
            cerr << errorMsg << endl;
            exitVal = 1;
        }
        e.usageMessage(e.getCmd());
        return exitVal;
    }
}

