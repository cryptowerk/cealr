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

#ifndef SEALER_PROPERTIES_H
#define SEALER_PROPERTIES_H
static const char *const DEFAULT_PROPERTIES = "~/.cealr/config.properties";

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <exception>
#include <map>

using namespace std;

class file_exception : public exception
{
private:
  runtime_error err_msg;
public:
  explicit file_exception(const string &file);

  virtual const char *what();
};

class properties : private map<string, string>
{
private:
  string file;
  bool saved;
public:
  explicit properties(const string &);

  properties();

  ~properties();

  void read_from_file();

  const string &getFile() const;

  bool operator==(const properties &) const;

  bool operator!=(const properties &) const;

  friend ostream &operator<<(ostream &, const properties &);

  string *get(const string &key, string *default_val = nullptr, bool cloneValue = true);

  void put(const string &key, const string &val);

  void remove(const string &key);

  void save();

  bool isSaved();

  void set_file(const string &fileName);

  static const string get_full_file_name(const string &file_name);
};

#endif //SEALER_PROPERTIES_H
