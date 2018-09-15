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
#include "properties.h"
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
  @brief constructor with command

  Constructor with command name
  */
  explicit print_usage_msg(const string &);

  /*!
  @brief constructor with command and error

  Constructor with command name and error message
  */
  print_usage_msg(string, string *);

  print_usage_msg();

  virtual const char *what();

  /*!
  @brief getter for command
  */
  string getCmd();

  /*!
  @brief print out usage message

  Method to print out the usage message to cout and errors to cerr
  */
  void usage_message(string cmd_name);
//    ~print_usage_msg()/* _NOEXCEPT override*/;
};

/*!
@brief main class of the tool

 This is the main implementation of the Cryptowerk sealing tool
cealr.run() is controlling the flow of cealr
*/
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
  bool reg_client;
  bool seal;
  bool sign;
  vector<string> file_names;
  string hex_hashes;
  string doc_names;
  properties *p_properties;

  void init_from_prop_if_null(string **p_string, string key);

  string *read_password();

  string hash_file(string file);

  void add2hashes(const string &file_name, const string *version);

public:
  cealr(int, const char **);

  virtual ~cealr();

  /*!
  @brief main method

  This method implements the general flow of
  */
  void run();

  /*!
  @brief calls the cryptowerk server to register a new client

  @param firstName     clients first name
  @param lastName      clients last name
  @param organization  clients organization if applicable

  @return parsed JSON response from server
  */
  json register_client(const string &firstName, const string &lastName, const string *organization) const;

  /*!
  @brief called for the first few usages of cealr

  This method is used for the first calls of the tool, until necessary account data are in properties
  */
  void init_properties();

  /*!
  @brief Getting account credentials with user name and password

  This method is called to retrieve account credentials from server using clients email and password.
  @param contains the clients password

  @return parsed JSON response from server
  */
  json creds(const string &password) const;

  /*!
  @brief Calling Cryptowerk API to seal a file

  This method is called to register the hash/signature of the file to be registered in the block chain that is
  assigned to the account.

  @param openPgpSign contains the signature of the file if the file has been signed. In this case the signature
          will be uploaded to the cryptowerk server to be registered as meta data of the file.

  @return parsed JSON response from server
  */
  json seal_file(const open_pgp *openPgpSign = nullptr) const;

  json verify_seal() const;

  /*!
  @brief Calling Cryptowerk API to retrieve seal a file and use the result to check the files authenticity

  This method is called to check if the hash/signature of a file ever was registered by cryptowerk in any block chain.
  It also checks (if possible):

   - If the hash of the file that is stored in the smart stamp matches the hash of the file to be verified

   - if the signature in the meta data matches the signature of the file to be verified in the case that the
     signature is there and the public pgp key is retreavable and trusted by the verifier.

   - If the hash of the file that is stored in the uploaded meta data matches the hash of the file to be verified

   It further prints out the email, the date the blockchain and the ID of the block chain transaction(s)
   for the registration event(s) of the file as wel as for the registration event(s) for the files meta data
   in any block chain. At the moment the verifying party needs to check the data inside these block chain transactions
   to make sure that the file was actually present at the time of the registration. The metod is trying provide all
   information necessary to make this verification as convinient as possible.

   //todo  However for the ultimate convinience this method needed to be extended to call the api of a
   //todo  block chain browser for the used block chain(s) and verify these root hashes themselves.

  @return parsed JSON response from server
  */
  void verify();

  void verify_metadata(SmartStamp &smartStamp);
};

#endif //CEALR_H
