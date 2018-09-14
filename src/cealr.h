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

#include <string>
#include <exception>
#include <cstdlib>
#include "Properties.h"
#include "open_pgp.h"
#include "smart_stamp.h"
#include <nlohmann/json.hpp>
#include <set>
#include <regex>

using json = nlohmann::json;

using namespace std;

/*!
@brief exception print_usage_message is used to inform how to call cealr

exception print_usage_message is thrown when command line parameters were not detected or wrong.
It causes to print the usage message for cealr
*/
class print_usage_msg : public exception
{
private:
  runtime_error err_msg;  //!< contains the part for cerr
  string cmd_name;        //!< param[0], the command itself (should be cealr)
public:
/*!
@brief method to print usage message

exception print_usage_message is thrown when command line parameters were not detected or wrong.
It causes to print the usage message for cealr
*/
  explicit print_usage_msg(const string &);

  print_usage_msg(string, string *);

  print_usage_msg();

  virtual const char *what();

  string getCmd();

  void usage_message(string cmd_name);
//    ~print_usage_msg()/* _NOEXCEPT override*/;
};

class cealr
{
private:
  string cmd_name;
  string *server;
  string *api_key;
  string *api_credential;
  string *email;
  bool verbose;
  bool register_arg_found;
  bool register_client;
  bool seal;
  bool sign;
  vector<string> file_names;
  string hex_hashes;
  string doc_names;
  Properties *properties;

  void init_from_prop_if_null(string **p_string, string key);

  string *read_password();

  string hash_file(string file);

  void add2hashes(const string &file_name, const string *version);

public:
  cealr(int, const char **);

  virtual ~cealr();

  void run();

  json register_user(const string &firstName, const string &lastName, const string *organization) const;

  json creds(const string &password) const;

  string *get_env_str(const string &) const;

  json seal_file(const open_pgp *openPgpSign = nullptr) const;

  json verify_seal() const;

  void verify();

  void verify_metadata(SmartStamp &smartStamp);
};

#endif //CEALR_H
