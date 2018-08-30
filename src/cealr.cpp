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

#include "cealr.h"
#include "curl_util.h"
#include "file_util.h"
#include <openssl/sha.h>
#include <zconf.h>
#include <sys/termios.h>

string *cealr::hash_file(const string file)
{
  ifstream ifs(file.c_str(), ifstream::binary);
  string *hash_hex = nullptr;
  if (ifs.is_open())
  {
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    ifs.unsetf(ios::skipws);
    ifs.seekg(0, std::ios::end);
    auto size = (unsigned long) ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    // reserve capacity
    unsigned long buf_size = (size < MAX_BUFFER_SIZE) ? size : MAX_BUFFER_SIZE;
    char buffer[buf_size];
    // read data
    unsigned long ptr = buf_size; // init with ptr after first read
    do
    {
      ifs.read(buffer, buf_size);
      SHA256_Update(&sha256_ctx, &buffer, buf_size);
      // since read does not return how many bytes are read, we have to keep track ourselves
      if ((ptr += buf_size) > size)
      {
        buf_size -= ptr - size;
        ptr = size;
      }
      // ifs.eof() is only true if we read beyond eof. We are keeping track of the remaining bytes to read and read
      // never more than available, so eof is never triggered and we have to exit based on buf_size==0
    } while (buf_size);
    ifs.close();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256_ctx);
    hash_hex = new string(to_hex(hash, SHA256_DIGEST_LENGTH));
  }
  else
  {
    stringstream what;
    what << "Cannot open file '" << file << "'.";
    string str_what = what.str();
    throw print_usage_msg(cmd_name, new string(str_what));
  }
  return hash_hex;
}

string cealr::to_hex(const unsigned char *hash, const int size)
{
  stringstream buf;
  for (int i = 0; i < size; i++)
  {
    buf << hex << setw(2) << setfill('0') << (int) hash[i];
  }

  return buf.str();
}

void print_usage_msg::usage_message(string cmd_name)
{
  const char *version =
#include "../VERSION"
;

  const char *sampleServerUrl = "https://devapi1.cryptowerk.com/platform";
  cout << "cealr v" << version << endl;
  cout << "Proof that file has not changed since registration:" << endl;
  cout << cmd_name << " [options] <file>" << endl;
  cout << endl;
  cout << "Usage for sealing own files:" << endl;
  cout << cmd_name << " [options] --seal <file>[@<version>]" << endl;
  cout << cmd_name << " [options] --sign <file>[@<version>]" << endl;
  cout << endl;
  cout << "  General options:" << endl;
  cout << "  --verbose         enable verbose output" << endl;
  cout << "  --server          server URL, e.g. '" << sampleServerUrl << "'" << endl;
  cout << endl;
  cout << "  Mode of operation, one of:" << endl;
  cout << "  --help            this help" << endl;
  cout << "  --register        to register a free account with CryptoWerk and store account credentials in "
       << DEFAULT_PROPERTIES << endl;
  cout << "  --seal [filename] register a document in blockchain(s)" << endl;
  cout << endl;
  cout << "Additional options with --seal:" << endl;
  cout << "  --update          Email update when submitted file is verifiable in blockchain" << endl;
  cout << "  --apiKey          API key, e.g. '" << "TskZZ8Zc2QzE3G+lxvUnWPKMk27Ucd1tm9K/YSPXWww=" << "'" << endl;
  cout << "  --apiCredential   API credential, e.g. ' " << "vV/2buaDD5aAcCQxCtk4WRJs/yK+BewThR1qUXikdJo=" << "'"
       << endl;
  cout << "  --login           to re-use an already registered account with CryptoWerk (or simply get the file "
       << DEFAULT_PROPERTIES << " from a system where you previously registered your account" << endl;
  cout << endl;
  cout << "Example for sealing:" << endl;
  cout << "  echo 'Hello, world.' >hello.txt" << endl;
  cout << "  " << cmd_name << " --seal hello.txt" << endl;
  cout << endl;
  cout << "Example verify a file" << endl;
  cout << "  " << cmd_name << " hello.txt" << endl;

}

char cealr::get_single_character_answer(const string &question, const set<char> valid_answers, const char default_answer)
{
  int c;
  bool ok;
  do
  {
    cout << question;
    cin.clear();
    string input;
    if (isatty(fileno(stdin)))
    {
      static struct termios currentTerminal, singleCharTerminal;
      tcgetattr(STDIN_FILENO, &currentTerminal);
      singleCharTerminal = currentTerminal;
      singleCharTerminal.c_lflag &= ~(ICANON);
      tcsetattr(STDIN_FILENO, TCSANOW, &singleCharTerminal);
      c = getchar();
      fflush(stdout);
      tcsetattr(STDIN_FILENO, TCSANOW, &currentTerminal);
    }
    else
    {
      getline(cin, input);
      c = input[0];
    }

    c = toupper(c);
    if (c == '\n' || c == 0)
    {
      c = default_answer;
    }
    else
    {
      cout << endl;
    }
    if (!(ok = (bool) valid_answers.count((char) c)))
    {
      cout << "Invalid answer, please try again" << endl;
    }
  } while (!ok);
  return (char) c;
}

string *cealr::get_string_matching(const string &question, regex regexp)
{
  bool ok;
  string input;
  do
  {
    cout << question;
    cin.clear();
    getline(cin, input);
    input = Properties::trim(input);
    smatch m;
    ok = regex_match(input, m, regexp);
    if (!ok)
    {
      cout << "Invalid answer, please try again" << endl;
    }
  } while (!ok);
  return new string(input);
}

string *cealr::get_password(const string &question, int min_length, int min_digits, int min_small, int min_caps)
{
  bool ok = false;
  string input;
  do
  {
    if (isatty(fileno(stdin)))
    {
      cin.clear();
      input = getpass(question.c_str());
    }
    else
    {
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
    if (length < min_length)
    {
      cout << "The password is not long enough: " << endl;
    }
    else
    {
      int digits, small, caps;
      digits = small = caps = 0;
      for (unsigned long i = 0; i < length; i++)
      {
        char c = input[i];
        if (c >= '0' && c <= '9')
        {
          digits++;
        }
        if (isupper(c))
        {
          small++;
        }
        if (isupper(c))
        {
          caps++;
        }
      }
      if (digits < min_digits)
      {
        cout << "The needs at least " << min_digits << " digits." << endl;
      }
      else if (small < min_small)
      {
        cout << "The needs at least " << min_small << " small letters." << endl;
      }
      else if (caps < min_caps)
      {
        cout << "The needs at least " << min_caps << " capital letters." << endl;
      }
      else
      {
        ok = true;
      }
    }
  } while (!ok);
  return new string(input);
}

string *cealr::get_opt_str(const string &question)
{
  string input;
  cout << question;
  cin.clear();
  getline(cin, input);
  input = Properties::trim(input);
  return (input[0]) == 0 ? nullptr : new string(input);
}

cealr::cealr(const int argc, const char **argv)
{
#ifndef NDEBUG
  //todo oz: Only for testing/debugging
  if (isatty(fileno(stdin)))
  {
    get_single_character_answer("Attach debugger?", {-1, 'N'}, 'N');
  }
#endif
  cmd_name = argc > 0 ? argv[0] : CEALR;
  verbose = false;

  properties = new Properties();
  cout << *properties << endl;

  // should call default constructor
  register_arg_found = false;
  register_client = false;
  seal = false;
  sign = false;
  server = nullptr;
  email = nullptr;
  api_key = nullptr;
  api_credential = nullptr;

  for (int i = 1; i < argc; i++)
  {
    string arg = argv[i];
    bool more_args = i + 1 < argc;
    bool call_add_to_hashes = false;
    if (arg == "--verbose")
    {
      verbose = true;
    }
    else if (arg == "--register" || arg == "--login")
    {
      register_client = arg == "--register";
      register_arg_found = true;
    }
    else if (i + 1 < argc && arg == "--seal")
    {
      seal = true;
      call_add_to_hashes = true;
      arg = argv[++i];
    }
    else if (i + 1 < argc && arg == "--sign")
    {
      seal = true;
      sign = true;
      call_add_to_hashes = true;
      arg = argv[++i];
    }
    else if (more_args && arg == "--server")
    {
      server = new string(argv[++i]);
    }
    else if (more_args && arg == "--apiKey")
    {
      api_key = new string(argv[++i]);
    }
    else if (more_args && arg == "--apiCredential")
    {
      api_credential = new string(argv[++i]);
    }
    else if (arg == "--help" || arg == "-h")
    {
      throw print_usage_msg(cmd_name);
    }
    else
    {
      call_add_to_hashes = true;
    }
    if (call_add_to_hashes)
    {
      string *version = nullptr;
      string *file_name = &arg;
      unsigned long verPos = arg.find_last_of('@');
      if (verPos != string::npos)
      {
        file_name = new string(arg.substr(0, verPos));
        version = new string(arg.substr(verPos + 1));
      }
      else
      {
        if (((i + 1) < argc) && (*argv[i + 1] == '@'))
        {
          version = new string(argv[++i] + 1); // skip @ character
        }
      }
      add2hashes(*file_name, version);
      if (version)
      {
        delete version;
        if (file_name != &arg)
        {
          delete file_name;
        }
      }
    }
  }
  if (api_key && !api_credential)
  {
    stringstream what;
    what << "The option --apiKey requires also the option --apiCredential." << endl
         << "You can use the option --apiCredential on its own if an apiKey" << endl
         << "is provided in properties or in environment variable \"CEALR_APIKEY\"" << endl
         << "to override the environment variable \"CEALR_APICREDENTIAL\"" << endl;

    throw print_usage_msg(cmd_name, new string(what.str()));
  }
  if (!api_key)
  {
    api_key = get_env_str("CEALR_APIKEY");
  }
  if (!api_credential)
  {
    api_credential = get_env_str("CEALR_APICREDENTIAL");
  }
}

void cealr::add2hashes(const string &file_name, const string *version)
{
  string *hash_hex = hash_file(file_name);
  if (!hex_hashes.empty())
  {
    hex_hashes.append(",");
  }
  hex_hashes.append(*hash_hex);
  file_names.push_back(file_name);
  string *doc_name = file_name_without_path(file_name);
  if (!doc_names.empty())
  {
    doc_names.append(",");
  }
  doc_names.append(*doc_name);
  if (version && !version->empty())
  {
    doc_names.append(" @");
    doc_names.append(*version);
  }
}

void cealr::run()
{
  if (!server)
  {
    server = properties->get("server", get_env_str("CEALR_SERVER"), false);
    if (!server)
    {
      server = new string(DEFAULT_SERVER);
    }
  }
  //in case of option --seal
  if (register_arg_found || (seal && !api_key && !properties->get("apiKey") && !properties->get("email")))
  {
    // ask if seal without apiKey
    if (!register_arg_found)
    {
      register_client = get_single_character_answer("Are you already registered with Cryptowerk? [y/N]: ", {'Y', 'N'}, 'N') == 'N';
    }
    regex email_pattern("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", regex_constants::icase);
    if (email && !regex_match(*email, email_pattern))
    {
      cout << "The parameter \"--email " << email << "\" was not accepted as a valid email address." << endl;
      email = nullptr;
    }
    //in case of registration ask for email, password, first name, last name and optional for org
    if (!email)
    {
      email = get_string_matching("Please enter your email address..................: ", email_pattern);
    }
    if (register_client)
    {
      //in case of registration ask for email, password, first name, last name and optional for org
      string first_name, last_name;
      regex name_pattern = regex("^[[:alpha:] \\-]+$");
      first_name = *get_string_matching("Please enter your first name.....................: ", name_pattern);
      last_name = *get_string_matching("Please enter your last name......................: ", name_pattern);
      string *organization = get_opt_str("Please enter your organization (if applicable)...: ");
      cout << endl << "Contacting server for user registration\"" << *server << "\"" << endl << endl;
      // register user
      json returnJson = register_user(first_name, last_name, organization);
      properties->remove("apiKey");
      // safe data on properties
      // inform about email confirmation
      cout << "You are now registered with our server \"" << *server << "\"." << endl
           << "An email has been sent to your account \"" << *email << "\"." << endl
           << "Please follow the instructions in this email to choose your password and" << endl
           << "to activate your account." << endl
           << "After account activation you will be able to use the cealr command line tool to " << endl
           << "seal files for proof of existence." << endl
           << endl;
    }
    properties->put("email", *email);
    if (*server != DEFAULT_SERVER)
    {
      properties->put("server", *server);
    }
    properties->remove("apiKey");
    properties->remove("apiCredential");
    properties->save();
    // todo No need to exit here, if user just has been created we could wait in cealr (password entry) for activation
    // todo or we exit here and they just need to start cealr again after activation
    if (register_client)
    {
      exit(1);
    }
  }
  if (seal)
  {
    init_from_prop_if_null(&api_key, "apiKey");
    init_from_prop_if_null(&api_credential, "apiCredential");
    init_from_prop_if_null(&email, "email");
    init_from_prop_if_null(&server, "server");
    if (!api_key || !api_key->length() || !api_credential || !api_credential->length())
    {
      string *password = read_password();
      cout << endl << "Contacting server \"" << *server << "\" to retrieve your account credentials." << endl << endl;
      json ret_json = creds(*password);
      cout << ret_json.dump() << endl;
      string str = ret_json["apiKey"];
      api_key = new string(str);
      str = ret_json["apiCredential"];
      api_credential = new string(str);
      if (!api_credential || !api_credential->length())
      {
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
      properties->put("apiKey", *api_key);
      properties->put("apiCredential", *api_credential);
      properties->save();
    }
  }
  if (hex_hashes.empty())
  {
    throw print_usage_msg(cmd_name, new string("Missing mode of operation. You might want to try option '--help'."));
  }
  if (seal)
  {
    if (sign)
    {
      open_pgp open_pgp(GPGME_SIG_MODE_DETACH, properties, email);
      for (const string &file_name:file_names)
      {
        open_pgp.sign(file_name);
        if (verbose)
        {
          json json = open_pgp.toJson();
          cout << "Signature: " << file_name << endl << json.dump() << endl;
        }
      }
      cout << endl << "Contacting server \"" << *server << "\" to seal your file \"" << doc_names << "\"" << endl
           << endl;
      seal_file(&open_pgp);
      cout << "File \"" << doc_names << "\" is successfully registered with Cryptowerk." << endl;
    }
    else
    {
      cout << endl << "Contacting server \"" << *server << "\" to seal your file \"" << doc_names << "\"" << endl
           << endl;
      seal_file();
      cout << "File \"" << doc_names << "\" is successfully registered with Cryptowerk." << endl;
    }
  }
  else
  {
    verify();
  }
}

void cealr::verify()
{
  const json &ret_json = verify_seal();
  auto docs = ret_json["documents"];
  if (docs != nullptr)
  {
    int found = docs.size();
    if (found)
    {
      cout << "A file with the same hash as \"" << this->doc_names << " has been registered with Cryptowerk " << found
           << " time(s)." << endl;
      cout << "Details:" << endl;
      // print out details for the document what blockchain(s), transaction(s), time registered
      // todo implement Verification as far as reasonable (traverse SmartStamp(s), verify signature, if it is there)!
      for (auto &doc : docs)
      {
        string doc_name = doc["name"];
        cout << "Submitted at " << this->format_time(doc["submittedAt"], "%H:%M:%ST%Y-%m-%d");
        if (doc_name.empty())
        {
          cout << " without name";
        }
        else
        {
          cout << " as " << doc_name;
        }
        cout << endl;
        auto bc_regs = doc["blockchainRegistrations"];
        if (bc_regs != NULL)
        {
          for (auto bcReg:bc_regs)
          {
            auto bcDesc = bcReg["blockChainDesc"];
            auto bc = bcDesc["generalName"];
            auto instance = bcDesc["instanceName"];
            cout << " put into blockchain: " << bc << ":" << instance << " at "
                 << this->format_time(bcReg["insertedIntoBlockchainAt"], "%H:%M:%ST%Y-%m-%d")
                 << ", Transaction ID: " << bcReg["blockChainId"] << endl;
          }
        }
        else
        {
          cout << endl << "There was no blockchain registration for this file." << endl;
        }
        verify_metadata(doc);
      }
    }
    else
    {
      cout << endl << "This file has not been registered with Cryptowerk." << endl;
    }
  }
  else
  {
    cerr << "unexpected answer from server: \"" << ret_json.dump() << "\"" << endl;
  }
}

void cealr::verify_metadata(json doc)
{
  auto sealed_meta_data = doc["sealedMetaData"];
  if (sealed_meta_data != nullptr)
  {
    // todo check MetaData hash and traverse metadata SmartStamp(s)
    // todo to root hash print out what root hash needs to be verified in which TX of which blockchain
    string sContent = sealed_meta_data["content"];
    auto content = json::parse(sContent); // keep string to build hash
    // check hash of sealed_meta_data, output verification info of sealed metadata
    auto doc_hash_meta = content["docHash"];
    if (this->hex_hashes != doc_hash_meta)
    {
      // todo if doc_hash_meta is null check if it works with string method on server
      // todo (convert hash to byte array add sContent as bytearray hash and ccompare
      // with leaf hash from meta data smartstamp)
      cout << "Meta data mismatch: The document hash in the metadata is not the hash of the file to be verified." << endl;
    }
    else
    {
      // verification and output of authenticity/signer
      string key_id = content["keyId"];
      string signature = content["signature"];
      open_pgp open_pgp(GPGME_SIG_MODE_DETACH, properties);
      for (const string &file_name:this->file_names)
      {
        json verification_js = open_pgp.verify(file_name, &signature);
        bool is_valid = verification_js["isValid"];
        cout << "The signature of \"" << file_name << "\" is " << (is_valid ? "matching" : "not matching")
             << " the stored signature on the server." << endl;
        cout << "The file was signed on " << this->format_time(verification_js["timestamp"], "%H:%M:%ST%Y-%m-%d")
             << " with the key with ID " << key_id << endl;
        auto name = verification_js["name"];
        if (name != nullptr)
        {
          cout << "The signing key belongs was issued by " << verification_js["name"] << endl;
        }
        else
        {
          cout << "The signing key has no name" << endl;
        }
        string signature_email = verification_js["email"];
        cout << "The email address in the signing key is " << signature_email;
        auto submitter_email = content["verifiedSubmitterEmail"];
        if (submitter_email != nullptr && (submitter_email == signature_email))
        {
          cout << " and matches the verified email address of the CryptoWerk customer who submitted this file for sealing.";
        }
        else
        {
          cout << endl << "However. The verified email address of the CryptoWerk customer who submitted this file for sealing is " << submitter_email;
        }
        cout << endl << endl;
      }
    }
  }
}

string cealr::format_time(time_t timestamp, string format)
{
  struct tm *time;
  char time_str[40];
  const time_t epoch = timestamp / 1000;
  time = localtime(&epoch);
  strftime(time_str, sizeof(time_str), format.c_str(), time);
  return string(time_str);
}

json cealr::seal_file(const open_pgp *openPgpSign) const
{
  json json;
  json["name"] = doc_names;
  json["contentType"] = *new string("application/octet-stream");
  json["store"] = true; //
  json["hashes"] = hex_hashes;
  json["publiclyRetrievable"] = true;
  if (openPgpSign)
  {
    json["sealedMetaDataJson"] = openPgpSign->toJson();
    // json["sealedMetaData"] = openPgpSign->toJson().dump(); // submitting as string
  }
  stringstream url;
  url << *server << "/API/v5/register";
  string _url = url.str();
  curl_util curl(_url, verbose);
  stringstream api_cred_str;
  api_cred_str << "X-ApiKey: " << *api_key << " " << *api_credential;
  const string api_creds = api_cred_str.str();
  curl.addHeader(api_creds);
  string *return_data = curl.post(json);
  auto ret_json = json::parse(*return_data);

  return ret_json;
}

json cealr::verify_seal() const
{
  json json;
  json["name"] = doc_names;
  json["contentType"] = *new string("application/octet-stream");
  json["retrievalDocHash"] = hex_hashes;
  json["provideRegistrarInfo"] = true;
  stringstream url;
  url << *server << "/API/v5/verify";
  string sUrl = url.str();
  curl_util curl(sUrl, verbose);
  curl.addHeader("X-ApiKey: TskZZ8Zc2QzE3G/lxvUnWPKMk27Ucd1tm9K+YSPXWww= vV+2buaDD5aAcCQxCtk4WRJs+yK/BewThR1qUXikdJo=");
//    string *returnData = new string("{\"maxSupportedAPIVersion\":5,\"documents\":[{\"retrievalId\":\"ri2179949c32bcc46560c9542cf0e48f981d0f26a6633ebbcedc9a96e3482416de1011b09\",\"registrarInfo\":{\"organization\":\"test\"},\"sealedMetaData\":{\"retrievalId\":\"ri2179950c388f94e32bd565762546d33015b9a901efd9c6cade59cda6bee0678d4024123\",\"data\":\"{\\\"key_id\\\":\\\"3965135F3C89FA95\\\",\\\"signature\\\":\\\" iQIyBAEBCAAdFiEEfLYAv3apQznh5CivOWUTXzyJ+pUFAluA4RQACgkQOWUTXzyJ +pXJlA/45RNwTnWCiS/qvyRdsCHn2e1It7PRJOq888PB5nro/7N9s8VYOtwK1067 DzAchwg65dnWfEv3OGgPCHiXJ2p2r5O71qCT7L/XGIeE0vZiex9p8nmCpi+5NkQ7 +MhWTPJpZLvAfmTIHPkFMuxChnZnqW6CBt9/aPO/DMv8/RmNztHwFLRuUUk7aR8M Uih8O1MD16xn4jvU8p0+7c9ZS5Vn/FlZv434sTNZmObXSZWtCmbnmYsxDBkFPezn fsWhp3oV1uPL/mMo2kEwPDYlIUhQAXB5A6rjZf4vDRMshziCzEQc1ZqSpzX7hqdc h5FRnqtgGKt7hVj79rg+BbDR9vyI1iKGSAsrmTpr7eSa5m2RXAk2rpSqW+2c8lU6 wjK1Q0sZI7JgNAFWZb7txj42IPAqaothBiTVnYztgR8jS0WgiGi89Ir4YvbR/o0s /61lvs8cPb0Smcvaa5kMxv6PUrUKNeqXk2hAH5bVyEOngzyIoBAaNRnCP31Y+YxE jB3tA0LUYXY0aw38hpWy9ZxWQQOLt9mc4e2SESfo2tZf8H4oTC+gDV6Nn4EYxgUo 6QFSMYljv9JOgL5ibggJJVnBU5LfizwmXv7vvw8dp851ognTBKyQ6DsH+4kMjdd9 Hw9uNdfezo+952O7dCZUY7AfDLXpozE7iGTKLNIyeKrXsangbA== =o0RX \\\"}\"},\"name\":\"CMakeCache.txt, sealed by olaf.zumpe@gmail.com\",\"submittedAt\":1535172960448,\"contentType\":\"application/octet-stream\",\"hasBeenInsertedIntoAtLeastOneBlockchain\":false,\"blockchainRegistrations\":[],\"hasBeenInsertedIntoAllRequestedBlockchains\":false}],\"minSupportedAPIVersion\":1}");
  string *return_data = curl.post(json);
  auto ret_json = json::parse(*return_data);

  return ret_json;
}

json cealr::register_user(const string &firstName, const string &lastName, const string *organization) const
{
  json json;
  json["email"] = *email;
  json["testAccountName"] = *email;
  json["optFirstName"] = firstName;
  json["optLastName"] = lastName;
  if (organization)
  {
    json["optOrganization"] = *organization;
  }
  stringstream url;
  url << *server << "/API/v5/registerUser";
  string sUrl = url.str();
  curl_util curl(sUrl, verbose);
  string *return_data = curl.post(json);
  auto ret_json = json::parse(*return_data);

  return ret_json;
}

json cealr::creds(const string &password) const
{
  json json;
  json["email"] = *email;
  json["password"] = password;
  stringstream url;
  url << *server << "/API/v5/creds";
  string sUrl = url.str();
  curl_util curl(sUrl, verbose);
  string *return_data = curl.post(json);
  auto ret_json = json::parse(*return_data);

  return ret_json;
}

string *cealr::read_password()
{
  string *password = nullptr;
  init_from_prop_if_null(&password, "password");
  if (!password)
  {
    password = get_env_str("CEALR_PASSWORD");
    if (!password)
    {
      stringstream question;
      question << "Please enter the password for your Cryptowerk account \"" << *email << "\" ";
      password = get_password(question.str(), 8, 0, 0, 0);
    }
  }

  return password;
}

string *cealr::get_env_str(const string &envKey) const
{
  string *envStr = nullptr;
  char *envPwd = getenv(envKey.c_str());
  if (envPwd)
  {
    envStr = new string(envPwd);
  }
  return envStr;
}

void cealr::init_from_prop_if_null(string **p_string, const string key)
{
  if (*p_string == nullptr)
  {
    *p_string = properties->get(key);
  }
}

cealr::~cealr()
{
  if (server)
  {
    delete server;
    server = nullptr;
  }
  if (api_key)
  {
    delete api_key;
    api_key = nullptr;
  }
  if (api_credential)
  {
    delete api_credential;
    api_credential = nullptr;
  }
  if (email)
  {
    delete email;
    email = nullptr;
  }
  if (properties)
  {
    delete properties;
    properties = nullptr;
  }

}

print_usage_msg::print_usage_msg(const string &command) : err_msg("")
{
  cmd_name = command;
}

const char *print_usage_msg::what()
{
  return err_msg.what();
}

string print_usage_msg::getCmd()
{
  return cmd_name;
}

print_usage_msg::print_usage_msg(const string command, string *error) : err_msg(error->c_str())
{
  cmd_name = command;
}

print_usage_msg::print_usage_msg() : err_msg("")
{
  cmd_name = "cealr";
}

//  --server https://devapi1.cryptowerk.com/platform --apiKey TskZZ8Zc2QzE3G/lxvUnWPKMk27Ucd1tm9K+YSPXWww= --api8888Credential vV+2buaDD5aAcCQxCtk4WRJs+yK/BewThR1qUXikdJo=
int main(int argc, const char **argv)
{
  try
  {
    cealr cealr(argc, argv);
    cealr.run();
  } catch (print_usage_msg &e)
  {
    int exit_val = 0;
    if (*e.what())
    {
      string errorMsg(e.what());
      cerr << errorMsg << endl;
      exit_val = 1;
    }
    e.usage_message(e.getCmd());
    return exit_val;
  }
  catch (pgp_exception &e)
  {
    cerr << e.what();
    exit(1);
  }
  catch (file_exception &e)
  {
    cerr << e.what();
    exit(1);
  }
}

