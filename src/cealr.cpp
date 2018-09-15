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

string cealr::hash_file(const string file)
{
  ifstream ifs(file.c_str(), ifstream::binary);
  string hash_hex;
  if (ifs.is_open())
  {
    hash_hex = getHashAsHex(ifs);
    ifs.close();
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

  p_properties = new properties();
  cout << *p_properties << endl;

  // should call default constructor
  register_arg_found = false;
  reg_client = false;
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
      reg_client = arg == "--register";
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
  if (!hex_hashes.empty())
  {
    hex_hashes.append(",");
  }
  hex_hashes.append(hash_file(file_name));
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
    server = p_properties->get("server", get_env_str("CEALR_SERVER"), false);
    if (!server)
    {
      server = new string(DEFAULT_SERVER);
    }
  }
  //in case of option --seal
  if (register_arg_found || (seal && !api_key && !p_properties->get("apiKey") && !p_properties->get("email")))
  {
    init_properties();
    // todo No need to exit here, if user just has been created we could wait in cealr (password entry) for activation
    // todo or we exit here and they just need to start cealr again after activation
    if (reg_client)
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
      p_properties->put("apiKey", *api_key);
      p_properties->put("apiCredential", *api_credential);
      p_properties->save();
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
      open_pgp open_pgp(GPGME_SIG_MODE_DETACH, p_properties, email);
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

void cealr::init_properties()
{
  // ask if seal without apiKey
  if (!register_arg_found)
  {
    reg_client = get_single_character_answer("Are you already registered with Cryptowerk? [y/N]: ", {'Y', 'N'}, 'N') == 'N';
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
  if (reg_client)
  {
    //in case of registration ask for email, password, first name, last name and optional for org
    string first_name, last_name;
    regex name_pattern = regex("^[[:alpha:] \\-]+$");
    first_name = *get_string_matching("Please enter your first name.....................: ", name_pattern);
    last_name = *get_string_matching("Please enter your last name......................: ", name_pattern);
    string *organization = get_opt_str("Please enter your organization (if applicable)...: ");
    cout << endl << "Contacting server for user registration\"" << *server << "\"" << endl << endl;
    // register user
    json returnJson = register_client(first_name, last_name, organization);
    p_properties->remove("apiKey");
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
  p_properties->put("email", *email);
  if (*server != DEFAULT_SERVER)
  {
    p_properties->put("server", *server);
  }
  p_properties->remove("apiKey");
  p_properties->remove("apiCredential");
  p_properties->save();
}

void cealr::verify()
{
  const json &ret_json = verify_seal();
//  const json &ret_json = json::parse("{\"maxSupportedAPIVersion\":5,\"documents\":[{\"retrievalId\":\"ri21728553502aace61892c04cb822308ace41937c2afa38acaabdda08ac56207cae7c3e3\",\"smartStamps\":[{\"data\":\"U1QFFAEHAAEOQ01ha2VDYWNoZS50eHQBGGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbQiJD3sic2lnbmF0dXJlIjoiIGlRSXpCQUVCQ0FBZEZpRUVmTFlBdjNhcFF6bmg1Q2l2T1dVVFh6eUorcFVGQWx1SFB6TUFDZ2tRT1dVVFh6eUogK3BVUU1BLy9hM3hSbWxFRjdYa21MT09aWjhnQTVRT1ZybytNazRVS0xjZWh4cXViYkRENER4Y0RBaEtFcXkzcyAwV3dRVXR3TkY5MldtaElWeHVLMVdaOUU1c0p0d0pERnYyemRrK1Uwc1JCbFFzZW85SHgzOVVWcENhQWNGTEk3IEp6dmE5Mk8zcTlUUGZxblFXeGdWaVpGNFdlWm9tOFJTYVlaRkJWUXpIUkticEIzNTRLVGw2UFVRS2R5TnhtcXEgdEp6UWlXREhISDF5RThiNE12WXdwb2NYR0VYc1ZoanZReVhpMjdhNmpiQVlkWmllVmVubkQ0MWZiZjJBelluQSBYVDhQWG5Way8yTktxMEc2VnhhY01KU0dvTDd4Wk9QR0RXOVVJVW9NZFNGck9haXQzQlBFWU5GOHoveXJncE5KIFpqWE5CZ2NBMFZheU50MjVtSHdDSEVZSitWWW1sWmcxZWdVYTFmWW56Zng5bkN5NDhnTEo5VlZyM1hBaTA5WVYgUWJQZVRZYi9maGZUU1hZc0pVcjlBUTFsNG1YL2s2NlE1T01zNWJKRnpKZkFZS0R6eGdvcFZMTFlrdzRDMkdqUiBYUUJkK0hBdW4yeUdaVjdIS2NzTC83Wk0zZDcyTzllaEFrVWlVYXNONWZCVm5LTkpYQ1dYNi8rc2VRb29JbjdnIFBVSE1PSEtGV1BidmlWWkdhZlNZMkEybE83OVZFOE1BUmV2RE9oMHRsNkRmc0UwTEw5VXVwLytkRmMxUjRRSFQgditFT2lWNURuY1NSRDJNQkwrWURJTHM1T3NjVzNJSVJxSHNDY0YwMTB6aVNnaUZOZHpMNDNjVnI1VEQ2TE56cyBnWmlEcDNBZkZYV3FYWnFxSzMyQzVKcjFZSEJ1UWVqTStLYkMrTE1lY1YrR1FLdE5Kb009ID1QS1JGICIsImtleVNlcnZlciI6InBncC5taXQuZWR1IiwiZG9jSGFzaCI6IjEzMGMxYzg4NmVlMThkYjgzYzhhYTE5MmZhNzdhMjAyYWE3MWU5OTA5ZmZlNTRkZDFkOTFlMGRjY2FiNjIxMzIiLCJrZXlJZCI6IjM5NjUxMzVGM0M4OUZBOTUiLCJ2ZXJpZmllZFN1Ym1pdHRlckVtYWlsIjoib2xhZi56dW1wZUBnbWFpbC5jb20ifQG+A1NUBRQBBwABE0NNYWtlQ2FjaGUudHh0Lm1ldGEBG2FwcGxpY2F0aW9uL2NyeXB0b3dlcmstbWV0YQUKTXVsdGljaGFpbgxtY2NyeXB0b3dlcmuAAWJhYzViYzI0YzBiNTE1Yjk4ZWQ0MjhlYWNmN2MyMDBkNjFhMDUyNmZkOWIyNzJjMTQyNjE1YmEyZDM0NmMzMTCi2fqEsVkBJ8llKDLpbb8ZhIBoR+o1lIeBRWobnTfnjLHGkOMR5hMDEwwciG7hjbg8iqGS+neiAqpx6ZCf/lTdHZHg3Mq2ITIEZSKroLW/eRrXFas+nr7+uZRfn9dyhtt1KDu0VgRmewYGBQpNdWx0aWNoYWluDG1jY3J5cHRvd2Vya4ABYmFjNWJjMjRjMGI1MTViOThlZDQyOGVhY2Y3YzIwMGQ2MWEwNTI2ZmQ5YjI3MmMxNDI2MTViYTJkMzQ2YzMxMKLZ+oSxWQETDByIbuGNuDyKoZL6d6ICqnHpkJ/+VN0dkeDcyrYhMgInyWUoMultvxmEgGhH6jWUh4FFahudN+eMscaQ4xHmEwRlIqugtb95GtcVqz6evv65lF+f13KG23UoO7RWBGZ7BgY=\"}],\"registrarInfo\":{\"organization\":\"test\"},\"sealedMetaData\":{\"retrievalId\":\"ri21728562f2d8793cafdf5ab1dcc13a0c69995f288bd3de3541a44d263500ff9f68afa03\",\"smartStamps\":[{\"data\":\"U1QFFAEHAAETQ01ha2VDYWNoZS50eHQubWV0YQEbYXBwbGljYXRpb24vY3J5cHRvd2Vyay1tZXRhBQpNdWx0aWNoYWluDG1jY3J5cHRvd2Vya4ABYmFjNWJjMjRjMGI1MTViOThlZDQyOGVhY2Y3YzIwMGQ2MWEwNTI2ZmQ5YjI3MmMxNDI2MTViYTJkMzQ2YzMxMKLZ+oSxWQEnyWUoMultvxmEgGhH6jWUh4FFahudN+eMscaQ4xHmEwMTDByIbuGNuDyKoZL6d6ICqnHpkJ/+VN0dkeDcyrYhMgRlIqugtb95GtcVqz6evv65lF+f13KG23UoO7RWBGZ7BgY=\"}],\"hasBeenInsertedIntoAtLeastOneBlockchain\":true,\"blockchainRegistrations\":[{\"blockChainId\":\"bac5bc24c0b515b98ed428eacf7c200d61a0526fd9b272c142615ba2d346c310\",\"insertedIntoBlockchainAt\":1535590225506,\"blockChainDesc\":{\"instanceName\":\"mccryptowerk\",\"generalName\":\"Multichain\"}}],\"content\":\"{\\\"signature\\\":\\\" iQIzBAEBCAAdFiEEfLYAv3apQznh5CivOWUTXzyJ+pUFAluHPzMACgkQOWUTXzyJ +pUQMA//a3xRmlEF7XkmLOOZZ8gA5QOVro+Mk4UKLcehxqubbDD4DxcDAhKEqy3s 0WwQUtwNF92WmhIVxuK1WZ9E5sJtwJDFv2zdk+U0sRBlQseo9Hx39UVpCaAcFLI7 Jzva92O3q9TPfqnQWxgViZF4WeZom8RSaYZFBVQzHRKbpB354KTl6PUQKdyNxmqq tJzQiWDHHH1yE8b4MvYwpocXGEXsVhjvQyXi27a6jbAYdZieVennD41fbf2AzYnA XT8PXnVk/2NKq0G6VxacMJSGoL7xZOPGDW9UIUoMdSFrOait3BPEYNF8z/yrgpNJ ZjXNBgcA0VayNt25mHwCHEYJ+VYmlZg1egUa1fYnzfx9nCy48gLJ9VVr3XAi09YV QbPeTYb/fhfTSXYsJUr9AQ1l4mX/k66Q5OMs5bJFzJfAYKDzxgopVLLYkw4C2GjR XQBd+HAun2yGZV7HKcsL/7ZM3d72O9ehAkUiUasN5fBVnKNJXCWX6/+seQooIn7g PUHMOHKFWPbviVZGafSY2A2lO79VE8MARevDOh0tl6DfsE0LL9Uup/+dFc1R4QHT v+EOiV5DncSRD2MBL+YDILs5OscW3IIRqHsCcF010ziSgiFNdzL43cVr5TD6LNzs gZiDp3AfFXWqXZqqK32C5Jr1YHBuQejM+KbC+LMecV+GQKtNJoM= =PKRF \\\",\\\"keyServer\\\":\\\"pgp.mit.edu\\\",\\\"docHash\\\":\\\"130c1c886ee18db83c8aa192fa77a202aa71e9909ffe54dd1d91e0dccab62132\\\",\\\"keyId\\\":\\\"3965135F3C89FA95\\\",\\\"verifiedSubmitterEmail\\\":\\\"olaf.zumpe@gmail.com\\\"}\"},\"name\":\"CMakeCache.txt\",\"submittedAt\":1535590203615,\"contentType\":\"application/octet-stream\",\"hasBeenInsertedIntoAtLeastOneBlockchain\":true,\"blockchainRegistrations\":[{\"blockChainId\":\"bac5bc24c0b515b98ed428eacf7c200d61a0526fd9b272c142615ba2d346c310\",\"insertedIntoBlockchainAt\":1535590225506,\"blockChainDesc\":{\"instanceName\":\"mccryptowerk\",\"generalName\":\"Multichain\"}}],\"hasBeenInsertedIntoAllRequestedBlockchains\":true},{\"retrievalId\":\"ri213018397ae2f7960d0efc668c40209a565d384b4e3aac440995d63c073078b3e9f08c8\",\"smartStamps\":[{\"data\":\"U1QFFAEHAAEOQ01ha2VDYWNoZS50eHQBGGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbQiJD3sic2lnbmF0dXJlIjoiIGlRSXpCQUVCQ0FBZEZpRUVmTFlBdjNhcFF6bmg1Q2l2T1dVVFh6eUorcFVGQWx1RndsUUFDZ2tRT1dVVFh6eUogK3BXeWlBLy9meXZkdkJpUmljdWRnWWF1VWdtN1lqLzNwVzc2SS8ySGVXc2k5OHE2aFM3bGhYdU5BNGJrMW90ZSA0WFAwRDNiVmRnRGF0UUFBRmorcDlzejFwQUlYYnVQNVpJOEExMW9EK0JZbGRJYm1UUUEzSXR5YkhZMjVtckhEIFJKdTVBOCtmcDhBVUFIUUhXR0xlb0RMWVJDWERrd3NuYXBWMHpVR29QT2g2dUxHbUZldlo5QzY3QWhGWVNyRSsga1hLT2o1SWN1NTVYTVRCM1pxbWZ2ZTZPOXVIaG5Va3M1NUFBZkNIQm94ZHpvV2FUSFc0UGZsTWpPWHBrdVpBSSA5dE1YenFZZXpTTy9SeS9kZUJKdE9jaHNwU0xlaUFlLzZxSllNL0sxOEttNEZZMkQxdFIyNFFBcXY2YWNzMnlIIDNZb09zWXYxOTQ1eGw2VUpPeFJ6QzY1anlzRDlORkxxeXVrK0JKUWIwWlBXQnVWckF2TlYybzEydjYyWmdTbEUgVzJTOVZYNmZ3d3AwV211ZXFIZ1hWVmJsdkx5Uzl4MksvaWZXR2tESkxQTHlmNWs2dEEwYzFnSkZOc1hYbit4UCBzeUdqNmdEQk9EYjMxYncwOCtMVlhSWTVzaldzNGQrK3Fxc05Mdno2MWxYVGdsSG5SUE0xbEJrbkMveW92emZ2IHN4RE40RWlDR05vakEyOUgreFVBL1VZVUc5WTdKMVdQQUR2NXBZU3VKb1JIM1FXd2tEV2RyS3ZrQ3JwYzdLTVggMy85azIyYVBoMmFMSjBOLzdwc2xuZUpaSytMTUNGSmJNb0IwRFNmVmhicjR0bEMvc0Z2WTQ1UXhGL0pSaTNaUSAyZlNjcFBZQzY4akpIVFlPM2FwMk54K0Y5VStKckNmVVkzWUFUMGYrVDIreUVFM1VhRTA9ID1kTCtXICIsImtleVNlcnZlciI6InBncC5taXQuZWR1IiwiZG9jSGFzaCI6IjEzMGMxYzg4NmVlMThkYjgzYzhhYTE5MmZhNzdhMjAyYWE3MWU5OTA5ZmZlNTRkZDFkOTFlMGRjY2FiNjIxMzIiLCJrZXlJZCI6IjM5NjUxMzVGM0M4OUZBOTUiLCJ2ZXJpZmllZFN1Ym1pdHRlckVtYWlsIjoib2xhZi56dW1wZUBnbWFpbC5jb20ifQG+A1NUBRQBBwABE0NNYWtlQ2FjaGUudHh0Lm1ldGEBG2FwcGxpY2F0aW9uL2NyeXB0b3dlcmstbWV0YQUKTXVsdGljaGFpbgxtY2NyeXB0b3dlcmuAATNhZTgxODM4MjcwMWM0MGZjODBiY2JmNWVlZWFkZjBlYTc0OWVkZjQxOTIxZjA0Mjg5NGZjMDQzOTljOWEyMGS2ppGosFkBKl8dpcuGqGpnsbEnZjQuNn2uf5dmNTkW+NuXjdZ1dU8DEwwciG7hjbg8iqGS+neiAqpx6ZCf/lTdHZHg3Mq2ITIE8pYOpQlrDndt+SJWnpp2FNruuU+QpIcbH8Dz/19/vTsGBQpNdWx0aWNoYWluDG1jY3J5cHRvd2Vya4ABM2FlODE4MzgyNzAxYzQwZmM4MGJjYmY1ZWVlYWRmMGVhNzQ5ZWRmNDE5MjFmMDQyODk0ZmMwNDM5OWM5YTIwZLamkaiwWQETDByIbuGNuDyKoZL6d6ICqnHpkJ/+VN0dkeDcyrYhMgIqXx2ly4aoamexsSdmNC42fa5/l2Y1ORb425eN1nV1TwTylg6lCWsOd235IlaemnYU2u65T5CkhxsfwPP/X3+9OwY=\"}],\"registrarInfo\":{\"organization\":\"test\"},\"sealedMetaData\":{\"retrievalId\":\"ri21301840d2b6615d83281a20fc227369e11fe70c87a8314a943573c80f2e7a7aae46038\",\"smartStamps\":[{\"data\":\"U1QFFAEHAAETQ01ha2VDYWNoZS50eHQubWV0YQEbYXBwbGljYXRpb24vY3J5cHRvd2Vyay1tZXRhBQpNdWx0aWNoYWluDG1jY3J5cHRvd2Vya4ABM2FlODE4MzgyNzAxYzQwZmM4MGJjYmY1ZWVlYWRmMGVhNzQ5ZWRmNDE5MjFmMDQyODk0ZmMwNDM5OWM5YTIwZLamkaiwWQEqXx2ly4aoamexsSdmNC42fa5/l2Y1ORb425eN1nV1TwMTDByIbuGNuDyKoZL6d6ICqnHpkJ/+VN0dkeDcyrYhMgTylg6lCWsOd235IlaemnYU2u65T5CkhxsfwPP/X3+9OwY=\"}],\"hasBeenInsertedIntoAtLeastOneBlockchain\":true,\"blockchainRegistrations\":[{\"blockChainId\":\"3ae818382701c40fc80bcbf5eeeadf0ea749edf41921f042894fc04399c9a20d\",\"insertedIntoBlockchainAt\":1535492893110,\"blockChainDesc\":{\"instanceName\":\"mccryptowerk\",\"generalName\":\"Multichain\"}}],\"content\":\"{\\\"signature\\\":\\\" iQIzBAEBCAAdFiEEfLYAv3apQznh5CivOWUTXzyJ+pUFAluFwlQACgkQOWUTXzyJ +pWyiA//fyvdvBiRicudgYauUgm7Yj/3pW76I/2HeWsi98q6hS7lhXuNA4bk1ote 4XP0D3bVdgDatQAAFj+p9sz1pAIXbuP5ZI8A11oD+BYldIbmTQA3ItybHY25mrHD RJu5A8+fp8AUAHQHWGLeoDLYRCXDkwsnapV0zUGoPOh6uLGmFevZ9C67AhFYSrE+ kXKOj5Icu55XMTB3Zqmfve6O9uHhnUks55AAfCHBoxdzoWaTHW4PflMjOXpkuZAI 9tMXzqYezSO/Ry/deBJtOchspSLeiAe/6qJYM/K18Km4FY2D1tR24QAqv6acs2yH 3YoOsYv1945xl6UJOxRzC65jysD9NFLqyuk+BJQb0ZPWBuVrAvNV2o12v62ZgSlE W2S9VX6fwwp0WmueqHgXVVblvLyS9x2K/ifWGkDJLPLyf5k6tA0c1gJFNsXXn+xP syGj6gDBODb31bw08+LVXRY5sjWs4d++qqsNLvz61lXTglHnRPM1lBknC/yovzfv sxDN4EiCGNojA29H+xUA/UYUG9Y7J1WPADv5pYSuJoRH3QWwkDWdrKvkCrpc7KMX 3/9k22aPh2aLJ0N/7pslneJZK+LMCFJbMoB0DSfVhbr4tlC/sFvY45QxF/JRi3ZQ 2fScpPYC68jJHTYO3ap2Nx+F9U+JrCfUY3YAT0f+T2+yEE3UaE0= =dL+W \\\",\\\"keyServer\\\":\\\"pgp.mit.edu\\\",\\\"docHash\\\":\\\"130c1c886ee18db83c8aa192fa77a202aa71e9909ffe54dd1d91e0dccab62132\\\",\\\"keyId\\\":\\\"3965135F3C89FA95\\\",\\\"verifiedSubmitterEmail\\\":\\\"olaf.zumpe@gmail.com\\\"}\"},\"name\":\"CMakeCache.txt\",\"submittedAt\":1535492831166,\"contentType\":\"application/octet-stream\",\"hasBeenInsertedIntoAtLeastOneBlockchain\":true,\"blockchainRegistrations\":[{\"blockChainId\":\"3ae818382701c40fc80bcbf5eeeadf0ea749edf41921f042894fc04399c9a20d\",\"insertedIntoBlockchainAt\":1535492893110,\"blockChainDesc\":{\"instanceName\":\"mccryptowerk\",\"generalName\":\"Multichain\"}}],\"hasBeenInsertedIntoAllRequestedBlockchains\":true},{\"retrievalId\":\"ri2199635a3a4937f266b9d00915b0c9527d85f21da9bf0888c07e04794003fb2072be816\",\"smartStamps\":[{\"data\":\"U1QFFAEHAAEOQ01ha2VDYWNoZS50eHQBGGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbQiCEHsic2lnbmF0dXJlIjoiIGlRSXpCQUVCQ0FBZEZpRUVmTFlBdjNhcFF6bmg1Q2l2T1dVVFh6eUorcFVGQWx1RnZSMEFDZ2tRT1dVVFh6eUogK3BVY0x3Ly9WV2R2bXpvOVJiTTI5UDJRSWowdlkwMTdoUzhPcWZiSVVmU2lWZ3I2KytoZ3dCclhrVStlc0dTRSBjSWsrcEJXc0djSGlrQnlVRUVmbFUwNWVvWHRFV3h2dWttT2UrM2E1bXNycDdwOHFMVFI4MVFqdy9RVDkxN2JQIFY4Q0xEaVd1VkRKWjBCSEF4MzYwRityYUlhMXpKMFR4eFoyYitJMHMwUC9pZGxNcWswRnFONS9ZOVVkUHBoU2oga2Mram9acEI3dlFydkNSMFpSYjQwVFNWOU93a2tjcUl0R0hRdmtjdU9YRVJWMEd0OE82S3RsRklIaTVjTUE4TSBELzZ2TVdiVWEwbFptMHdBN2FsMmpZbEZpMkNkQVJJNjI3dmxaSHcyRUhBMTBlcDIwaGZHbHc4ZlZydGRZOWhKIExjd3pGbDg2VnoydXZBeUZTekViem1PdW90REpKRzByNXRMWk1MVVNHcHI1MlRZZWxDcUpnR0xxWnNuL3kxSTcgZEhiSVdWVEp2Sm5CdXY4NXNvUFMxNHcwdG15VlN5eXNCNkIxbXlCSXB0dlB4VHdjTWV5dTJEeWxMQW1hM3N0WCArTkhrYmh3RURNR1Ztc2JMazEwYjRMTGVCM011S2FRbWNIYmo5b3lmVklqbDhDaUFJeDBnNEV4Q0pFSy9QV2FGIFFPTkwyQXZRdTZNbUUrWEcrN3NUa1dZM0RvR0RHbkFRYUZGU0tUWW41amFLUEhXdXZnMkQ1bjA3Yi8zMlluS3MgTWVFYmk1WTd4dUNkK3ZPSG9kYlduWXdNQksyb2VCVDZaeEJvTktZRUpGc2FUTWwrVnJBSCs1c0Z5MTBwY0RMbiBmcDVNdlhuR3pnRy9ZTWJ6V0JHVHdOU2cwcGpHTGZDdmkzUlBpVHhFVzRqdlpUbFVOMXM9ID1qR1ViICIsImtleVNlcnZlciI6InBncC5taXQuZWR1IiwiZG9jSGFzaCI6WzE5LDEyLDI4LC0xMjAsMTEwLC0zMSwtMTE1LC03Miw2MCwtMTE4LC05NSwtMTEwLC02LDExOSwtOTQsMiwtODYsMTEzLC0yMywtMTEyLC05NywtMiw4NCwtMzUsMjksLTExMSwtMzIsLTM2LC01NCwtNzQsMzMsNTBdLCJrZXlJZCI6IjM5NjUxMzVGM0M4OUZBOTUiLCJ2ZXJpZmllZFN1Ym1pdHRlckVtYWlsIjoib2xhZi56dW1wZUBnbWFpbC5jb20ifQG+A1NUBRQBBwABE0NNYWtlQ2FjaGUudHh0Lm1ldGEBG2FwcGxpY2F0aW9uL2NyeXB0b3dlcmstbWV0YQUKTXVsdGljaGFpbgxtY2NyeXB0b3dlcmuAAWRiZjFlYmRiZTBmNTI2Y2IyYmZhMjg3YzBkZGYxNjk1MmRlZTI1Y2I4NjVkZTEzMTJjM2IwYzFhNDhkM2ZmYTWyveGmsFkBRb6XQJGRS85s0rKp0FGJmSeOK63niU/QJO5TLtACzFYDEwwciG7hjbg8iqGS+neiAqpx6ZCf/lTdHZHg3Mq2ITIEtRc7f8lugCrz9XgPbAjHugZ8bM9FcRu9GR5AG/eiA1QGBQpNdWx0aWNoYWluDG1jY3J5cHRvd2Vya4ABZGJmMWViZGJlMGY1MjZjYjJiZmEyODdjMGRkZjE2OTUyZGVlMjVjYjg2NWRlMTMxMmMzYjBjMWE0OGQzZmZhNbK94aawWQETDByIbuGNuDyKoZL6d6ICqnHpkJ/+VN0dkeDcyrYhMgJFvpdAkZFLzmzSsqnQUYmZJ44rreeJT9Ak7lMu0ALMVgS1Fzt/yW6AKvP1eA9sCMe6Bnxsz0VxG70ZHkAb96IDVAY=\"}],\"registrarInfo\":{\"organization\":\"test\"},\"sealedMetaData\":{\"retrievalId\":\"ri219963632c7f4442238445afec31293d5af83a43cbb369f004bf6eeba7e39d16b56a2f4\",\"smartStamps\":[{\"data\":\"U1QFFAEHAAETQ01ha2VDYWNoZS50eHQubWV0YQEbYXBwbGljYXRpb24vY3J5cHRvd2Vyay1tZXRhBQpNdWx0aWNoYWluDG1jY3J5cHRvd2Vya4ABZGJmMWViZGJlMGY1MjZjYjJiZmEyODdjMGRkZjE2OTUyZGVlMjVjYjg2NWRlMTMxMmMzYjBjMWE0OGQzZmZhNbK94aawWQFFvpdAkZFLzmzSsqnQUYmZJ44rreeJT9Ak7lMu0ALMVgMTDByIbuGNuDyKoZL6d6ICqnHpkJ/+VN0dkeDcyrYhMgS1Fzt/yW6AKvP1eA9sCMe6Bnxsz0VxG70ZHkAb96IDVAY=\"}],\"hasBeenInsertedIntoAtLeastOneBlockchain\":true,\"blockchainRegistrations\":[{\"blockChainId\":\"dbf1ebdbe0f526cb2bfa287c0ddf16952dee25cb865de1312c3b0c1a48d3ffa5\",\"insertedIntoBlockchainAt\":1535491452786,\"blockChainDesc\":{\"instanceName\":\"mccryptowerk\",\"generalName\":\"Multichain\"}}],\"content\":\"{\\\"signature\\\":\\\" iQIzBAEBCAAdFiEEfLYAv3apQznh5CivOWUTXzyJ+pUFAluFvR0ACgkQOWUTXzyJ +pUcLw//VWdvmzo9RbM29P2QIj0vY017hS8OqfbIUfSiVgr6++hgwBrXkU+esGSE cIk+pBWsGcHikByUEEflU05eoXtEWxvukmOe+3a5msrp7p8qLTR81Qjw/QT917bP V8CLDiWuVDJZ0BHAx360F+raIa1zJ0TxxZ2b+I0s0P/idlMqk0FqN5/Y9UdPphSj kc+joZpB7vQrvCR0ZRb40TSV9OwkkcqItGHQvkcuOXERV0Gt8O6KtlFIHi5cMA8M D/6vMWbUa0lZm0wA7al2jYlFi2CdARI627vlZHw2EHA10ep20hfGlw8fVrtdY9hJ LcwzFl86Vz2uvAyFSzEbzmOuotDJJG0r5tLZMLUSGpr52TYelCqJgGLqZsn/y1I7 dHbIWVTJvJnBuv85soPS14w0tmyVSyysB6B1myBIptvPxTwcMeyu2DylLAma3stX +NHkbhwEDMGVmsbLk10b4LLeB3MuKaQmcHbj9oyfVIjl8CiAIx0g4ExCJEK/PWaF QONL2AvQu6MmE+XG+7sTkWY3DoGDGnAQaFFSKTYn5jaKPHWuvg2D5n07b/32YnKs MeEbi5Y7xuCd+vOHodbWnYwMBK2oeBT6ZxBoNKYEJFsaTMl+VrAH+5sFy10pcDLn fp5MvXnGzgG/YMbzWBGTwNSg0pjGLfCvi3RPiTxEW4jvZTlUN1s= =jGUb \\\",\\\"keyServer\\\":\\\"pgp.mit.edu\\\",\\\"docHash\\\":[19,12,28,-120,110,-31,-115,-72,60,-118,-95,-110,-6,119,-94,2,-86,113,-23,-112,-97,-2,84,-35,29,-111,-32,-36,-54,-74,33,50],\\\"keyId\\\":\\\"3965135F3C89FA95\\\",\\\"verifiedSubmitterEmail\\\":\\\"olaf.zumpe@gmail.com\\\"}\"},\"name\":\"CMakeCache.txt\",\"submittedAt\":1535491422581,\"contentType\":\"application/octet-stream\",\"hasBeenInsertedIntoAtLeastOneBlockchain\":true,\"blockchainRegistrations\":[{\"blockChainId\":\"dbf1ebdbe0f526cb2bfa287c0ddf16952dee25cb865de1312c3b0c1a48d3ffa5\",\"insertedIntoBlockchainAt\":1535491452786,\"blockChainDesc\":{\"instanceName\":\"mccryptowerk\",\"generalName\":\"Multichain\"}}],\"hasBeenInsertedIntoAllRequestedBlockchains\":true},{\"retrievalId\":\"ri2179949c32bcc46560c9542cf0e48f981d0f26a6633ebbcedc9a96e3482416de1011b09\",\"smartStamps\":[{\"data\":\"U1QFFAEHAAEuQ01ha2VDYWNoZS50eHQsIHNlYWxlZCBieSBvbGFmLnp1bXBlQGdtYWlsLmNvbQEYYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtCLIMeyJrZXlJZCI6IjM5NjUxMzVGM0M4OUZBOTUiLCJzaWduYXR1cmUiOiIgaVFJeUJBRUJDQUFkRmlFRWZMWUF2M2FwUXpuaDVDaXZPV1VUWHp5SitwVUZBbHVBNFJRQUNna1FPV1VUWHp5SiArcFhKbEEvNDVSTndUbldDaVMvcXZ5UmRzQ0huMmUxSXQ3UFJKT3E4ODhQQjVucm8vN045czhWWU90d0sxMDY3IER6QWNod2c2NWRuV2ZFdjNPR2dQQ0hpWEoycDJyNU83MXFDVDdML1hHSWVFMHZaaWV4OXA4bm1DcGkrNU5rUTcgK01oV1RQSnBaTHZBZm1USUhQa0ZNdXhDaG5abnFXNkNCdDkvYVBPL0RNdjgvUm1OenRId0ZMUnVVVWs3YVI4TSBVaWg4TzFNRDE2eG40anZVOHAwKzdjOVpTNVZuL0ZsWnY0MzRzVE5abU9iWFNaV3RDbWJubVlzeERCa0ZQZXpuIGZzV2hwM29WMXVQTC9tTW8ya0V3UERZbElVaFFBWEI1QTZyalpmNHZEUk1zaHppQ3pFUWMxWnFTcHpYN2hxZGMgaDVGUm5xdGdHS3Q3aFZqNzlyZytCYkRSOXZ5STFpS0dTQXNybVRwcjdlU2E1bTJSWEFrMnJwU3FXKzJjOGxVNiB3aksxUTBzWkk3SmdOQUZXWmI3dHhqNDJJUEFxYW90aEJpVFZuWXp0Z1I4alMwV2dpR2k4OUlyNFl2YlIvbzBzIC82MWx2czhjUGIwU21jdmFhNWtNeHY2UFVyVUtOZXFYazJoQUg1YlZ5RU9uZ3p5SW9CQWFOUm5DUDMxWStZeEUgakIzdEEwTFVZWFkwYXczOGhwV3k5WnhXUVFPTHQ5bWM0ZTJTRVNmbzJ0WmY4SDRvVEMrZ0RWNk5uNEVZeGdVbyA2UUZTTVlsanY5Sk9nTDVpYmdnSkpWbkJVNUxmaXp3bVh2N3Z2dzhkcDg1MW9nblRCS3lRNkRzSCs0a01qZGQ5IEh3OXVOZGZlem8rOTUyTzdkQ1pVWTdBZkRMWHBvekU3aUdUS0xOSXllS3JYc2FuZ2JBPT0gPW8wUlggIn0BngRTVAUUAQcAATNDTWFrZUNhY2hlLnR4dCwgc2VhbGVkIGJ5IG9sYWYuenVtcGVAZ21haWwuY29tLm1ldGEBG2FwcGxpY2F0aW9uL2NyeXB0b3dlcmstbWV0YQUKTXVsdGljaGFpbgxtY2NyeXB0b3dlcmuAATdmOTA2ZWY3MWJjNDUxMjA4ZWUxM2NmOWExM2EyZjc1ZDUyM2M3YzQ3ZTkyMWQ5YTMzNjQzN2JjZGJiMTgyOTGRvZWbrlkBNfzYEUM+hG7s2B0CgNtmxOol97xLK9zIAeoxRshI02UDEwwciG7hjbg8iqGS+neiAqpx6ZCf/lTdHZHg3Mq2ITIExSDasFDkL9O2/vdUzKY1F0Rw1FK5xWcO6dLBbM+/5tsGBQpNdWx0aWNoYWluDG1jY3J5cHRvd2Vya4ABN2Y5MDZlZjcxYmM0NTEyMDhlZTEzY2Y5YTEzYTJmNzVkNTIzYzdjNDdlOTIxZDlhMzM2NDM3YmNkYmIxODI5MZG9lZuuWQETDByIbuGNuDyKoZL6d6ICqnHpkJ/+VN0dkeDcyrYhMgI1/NgRQz6EbuzYHQKA22bE6iX3vEsr3MgB6jFGyEjTZQTFINqwUOQv07b+91TMpjUXRHDUUrnFZw7p0sFsz7/m2wY=\"}],\"registrarInfo\":{\"organization\":\"test\"},\"sealedMetaData\":{\"retrievalId\":\"ri2179950c388f94e32bd565762546d33015b9a901efd9c6cade59cda6bee0678d4024123\",\"smartStamps\":[{\"data\":\"U1QFFAEHAAEzQ01ha2VDYWNoZS50eHQsIHNlYWxlZCBieSBvbGFmLnp1bXBlQGdtYWlsLmNvbS5tZXRhARthcHBsaWNhdGlvbi9jcnlwdG93ZXJrLW1ldGEFCk11bHRpY2hhaW4MbWNjcnlwdG93ZXJrgAE3ZjkwNmVmNzFiYzQ1MTIwOGVlMTNjZjlhMTNhMmY3NWQ1MjNjN2M0N2U5MjFkOWEzMzY0MzdiY2RiYjE4Mjkxkb2Vm65ZATX82BFDPoRu7NgdAoDbZsTqJfe8SyvcyAHqMUbISNNlAxMMHIhu4Y24PIqhkvp3ogKqcemQn/5U3R2R4NzKtiEyBMUg2rBQ5C/Ttv73VMymNRdEcNRSucVnDunSwWzPv+bbBg==\"}],\"hasBeenInsertedIntoAtLeastOneBlockchain\":true,\"blockchainRegistrations\":[{\"blockChainId\":\"7f906ef71bc451208ee13cf9a13a2f75d523c7c47e921d9a336437bcdbb18291\",\"insertedIntoBlockchainAt\":1535210860369,\"blockChainDesc\":{\"instanceName\":\"mccryptowerk\",\"generalName\":\"Multichain\"}}],\"content\":\"{\\\"keyId\\\":\\\"3965135F3C89FA95\\\",\\\"signature\\\":\\\" iQIyBAEBCAAdFiEEfLYAv3apQznh5CivOWUTXzyJ+pUFAluA4RQACgkQOWUTXzyJ +pXJlA/45RNwTnWCiS/qvyRdsCHn2e1It7PRJOq888PB5nro/7N9s8VYOtwK1067 DzAchwg65dnWfEv3OGgPCHiXJ2p2r5O71qCT7L/XGIeE0vZiex9p8nmCpi+5NkQ7 +MhWTPJpZLvAfmTIHPkFMuxChnZnqW6CBt9/aPO/DMv8/RmNztHwFLRuUUk7aR8M Uih8O1MD16xn4jvU8p0+7c9ZS5Vn/FlZv434sTNZmObXSZWtCmbnmYsxDBkFPezn fsWhp3oV1uPL/mMo2kEwPDYlIUhQAXB5A6rjZf4vDRMshziCzEQc1ZqSpzX7hqdc h5FRnqtgGKt7hVj79rg+BbDR9vyI1iKGSAsrmTpr7eSa5m2RXAk2rpSqW+2c8lU6 wjK1Q0sZI7JgNAFWZb7txj42IPAqaothBiTVnYztgR8jS0WgiGi89Ir4YvbR/o0s /61lvs8cPb0Smcvaa5kMxv6PUrUKNeqXk2hAH5bVyEOngzyIoBAaNRnCP31Y+YxE jB3tA0LUYXY0aw38hpWy9ZxWQQOLt9mc4e2SESfo2tZf8H4oTC+gDV6Nn4EYxgUo 6QFSMYljv9JOgL5ibggJJVnBU5LfizwmXv7vvw8dp851ognTBKyQ6DsH+4kMjdd9 Hw9uNdfezo+952O7dCZUY7AfDLXpozE7iGTKLNIyeKrXsangbA== =o0RX \\\"}\"},\"name\":\"CMakeCache.txt, sealed by olaf.zumpe@gmail.com\",\"submittedAt\":1535172960448,\"contentType\":\"application/octet-stream\",\"hasBeenInsertedIntoAtLeastOneBlockchain\":true,\"blockchainRegistrations\":[{\"blockChainId\":\"7f906ef71bc451208ee13cf9a13a2f75d523c7c47e921d9a336437bcdbb18291\",\"insertedIntoBlockchainAt\":1535210860369,\"blockChainDesc\":{\"instanceName\":\"mccryptowerk\",\"generalName\":\"Multichain\"}}],\"hasBeenInsertedIntoAllRequestedBlockchains\":true}],\"minSupportedAPIVersion\":1}");
  auto docs = ret_json["documents"];
  if (docs != nullptr)
  {
    int found = docs.size();
    if (found)
    {
      cout << "A file with the same hash as \"" << doc_names << " has been registered with Cryptowerk " << found
           << " time(s)." << endl;
      cout << "Details:" << endl;
      // print out details for the document what blockchain(s), transaction(s), time registered
      // Verification (traverse SmartStamp(s), verify signature, if it is there)!
      for (auto &doc : docs)
      {
        string doc_name = doc["name"];
        cout << "Submitted at " << format_time(doc["submittedAt"], "%H:%M:%ST%Y-%m-%d");
        if (doc_name.empty())
        {
          cout << " without name";
        }
        else
        {
          cout << " as " << doc_name;
        }
        cout << endl;
        //todo implement minimalistic server response for better scalability
//        auto bc_regs = doc["blockchainRegistrations"];
//        if (bc_regs != NULL)
//        {
//          for (auto bcReg:bc_regs)
//          {
//            auto bcDesc = bcReg["blockChainDesc"];
//            auto bc = bcDesc["generalName"];
//            auto instance = bcDesc["instanceName"];
//            cout << " put into blockchain: " << bc << ":" << instance << " at "
//                 << format_time(bcReg["insertedIntoBlockchainAt"], "%H:%M:%ST%Y-%m-%d")
//                 << ", Transaction ID: " << bcReg["blockChainId"] << endl;
//          }
//        }
//        else
//        {
//          cout << endl << "There was no blockchain registration for this file." << endl;
//        }
        //todo minimize server response to one smart stamp
//        verify_metadata(doc);
        const auto smartStamps = doc["smartStamps"];
        if (smartStamps!= nullptr)
        {
          const auto sObj = smartStamps[0];
          string smartStampTextualRepresentation = sObj["data"];
          SmartStamp smartStamp(smartStampTextualRepresentation);
          smartStamp.initFields();
          auto bc = smartStamp.getBlockchain();
          auto bcDesc = bc->getBlockChainDesc()->toString();
          // todo: output verification value (SW+root hash) to verify it in bc browser
          cout << " Registered with blockchain: " << bcDesc << " at "
               << format_time(bc->getInsertedIntoBlockchainAt(), "%H:%M:%ST%Y-%m-%d")
               << ", Transaction ID: " << bc->getBlockChainId() << endl;
          // and analyze metadata from document smart stamp
          verify_metadata(smartStamp);

          vector<char> hash = from_hex(hex_hashes);
          // todo if root is retrievable by bc call with:
          // SmartStamp::VerificationResult verificationResult=smartStamp.verifyByHash((unsigned char *) &(hash[0]), anchorInBlockchain, nullptr, true);
          SmartStamp::VerificationResult *verificationResult = smartStamp.verifyByHash((unsigned char *) &(hash[0]), nullptr, true);
            if (verificationResult->hasBeenVerified())
            {
              cout << "The verification of the smart stamp was successful" << endl;
            }
            else
            {
              cout << "The hash of the file does not match the stored hash in the smart stamp. Verification failed!" << endl;
            }
        }
        else
        {
          cout << endl << "There was no blockchain registration for this file." << endl;
        }
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

void cealr::verify_metadata(SmartStamp &smartStamp)
{
  auto sealed_meta_data = smartStamp.getSealedMetaData();
  if (sealed_meta_data != nullptr)
  {
    const auto sealedContent = *sealed_meta_data->getData();
        auto content = json::parse(sealedContent); // keep string to build hash
    // check hash of sealed_meta_data, output verification info of sealed metadata
    auto doc_hash_meta = content["docHash"];
    const auto hasJson = doc_hash_meta != nullptr;
    istream *is;
    if (hasJson)
    {
      is = new istringstream(sealedContent);
    }
    else
    {
      // in this case we need to append the document hash to the stream before we create the meta data hash 
      vector<char> v1(sealedContent.begin(), sealedContent.end());
      auto hash = smartStamp.getDocHash();
      v1.insert(v1.end(), hash, hash+SHA256_DIGEST_LENGTH);
      is = new istringstream(string(&v1[0],v1.size()));
    }
    unsigned char metadataHash[SHA256_DIGEST_LENGTH];
    getHash(*is, metadataHash);
    delete is;
    for (vector<char> &smStamp:*sealed_meta_data->getMetaDataStamps())
    {
      SmartStamp smartStampMeta(smStamp);
      SmartStamp::VerificationResult *md_verified = smartStampMeta.verifyByHash(metadataHash, nullptr, false);
      if (md_verified->hasBeenVerified())
      {
        auto bc = smartStampMeta.getBlockchain();
        auto bcDesc = bc->getBlockChainDesc()->toString();
        string regDat;
        unsigned char _sw[] {'S','W'};
        regDat.append(to_hex(_sw, 2));
        auto str = to_hex(smartStampMeta.getRootHash(), SHA256_DIGEST_LENGTH);
        regDat.append(str);
        cout << " Metadata is valid and must have been registered with blockchain: " << bcDesc << " at "
             << format_time(bc->getInsertedIntoBlockchainAt(), "%H:%M:%ST%Y-%m-%d")
             << ", Transaction ID: " << bc->getBlockChainId() << endl
             << " Please verify that the data in this transaction is \"" << regDat << "\"." << endl;
      }
      else
      {
        cout << "The hash over the meta data does not match the hash in the meta data smart stamp. Verification failed. The data seems to be corrupted." << endl;
        return;
      }
    }

    if (hasJson)
    {
      // verification and output of authenticity/signer
      if (content.count("signature"))
      {
        string signature = content["signature"];
        if (verbose)
        {
          cout << endl << "The metadata contains a signature of a file. Trying to verify it ..." << endl << endl;
        }
        string key_id = content["keyId"];
        open_pgp open_pgp(GPGME_SIG_MODE_DETACH, p_properties);
        for (const string &file_name:file_names)
        {
          json verification_js = open_pgp.verify(file_name, &signature);
          if (verbose)
          {
            cout << verification_js.dump(2, ' ', false) << endl;
          }
          bool is_valid = verification_js["isValid"];
          cout << "The signature of \"" << file_name << "\" is " << (is_valid ? "matching" : "not matching")
               << " the stored signature on the server." << endl;
          if (is_valid)
          {
            cout << "The file was signed on " << format_time(verification_js["timestamp"], "%H:%M:%ST%Y-%m-%d")
                 << " with the key with ID " << key_id << endl;
            auto name = verification_js["name"];
            if (name != nullptr)
            {
              cout << "The signing key was issued by " << verification_js["name"] << endl;
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
              cout
                  << " and matches the verified email address of the CryptoWerk customer who submitted this file for sealing.";
            }
            else
            {
              cout << endl
                   << "However. The verified email address of the CryptoWerk customer who submitted this file for sealing is "
                   << submitter_email;
            }
            cout << endl << endl;
          }
        }
      }
    }
    else
    {
      cout << "Metadata has valid tata in it. It cannot be verified by this cealr version" << endl;
    }
  }
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

json cealr::register_client(const string &firstName, const string &lastName, const string *organization) const
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
      string nttyErr = "Password input is only possible when cealr is started in interactive mode.\n"
                       "Currently the standard input is not a console.\n"
                       "Please use one of the options below to enter your password:\n"
                       " - start cealr directly in a the command line in a console\n"
                       " - set the environment variable CEALR_PASSWORD\n"
                       " - add line password=<your password>\n"
                       "   in the file \"" + p_properties->getFile() + "\"\n";
      password = get_password(question.str(), 8, 0, 0, 0, nttyErr);
    }
  }

  return password;
}

void cealr::init_from_prop_if_null(string **p_string, const string key)
{
  if (*p_string == nullptr)
  {
    *p_string = p_properties->get(key);
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
  if (p_properties)
  {
    delete p_properties;
    p_properties = nullptr;
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
    cerr << e.what() << endl;
    exit(1);
  }
  catch (base64_exception &e)
  {
    cerr << e.what() << endl;
    exit(1);
  }
  catch (SmartStampError &e)
  {
    cerr << e.what() << endl;
    exit(1);
  }
  catch (file_exception &e)
  {
    cerr << e.what() << endl;
    exit(1);
  }
  catch (exception &e)
  {
    cerr << e.what() << endl;
    exit(1);
  }
}

