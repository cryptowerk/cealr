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

/*!
@brief exception thrown in case of errors during opening files
*/
class file_exception : public exception
{
private:
  runtime_error err_msg;
public:
  explicit file_exception(const string &file);

  virtual const char *what();
};

/*!
@brief handling property files as key/value maps
*/
class properties : private map<string, string>
{
private:
  string file;  //!< physical file containing properties in form <key> = <value>
  bool saved;   //!< is true when properties have changed, otherwise false
public:
  /*!
  @brief constructor with file name
  @param file_name is the name of the property file
  */
  explicit properties(const string &);

  properties();

  ~properties();

  /*!
  @brief reading property files into this object (interpreted as a map)

  This method is reading from files that contains lines in the format

  <key> = <value>
    or
  #<comment>

  and assigning it to (*this)[key] = value;
  */
  void read_from_file();

  /*!
  @brief getter for file name

  This method returns the name and the path of the properties file

  @return the name and the path of the properties file
  */
  const string &getFile() const;

  bool operator==(const properties &) const;

  bool operator!=(const properties &) const;

  /*!
  @brief dumps properties into output stream

  This override serves the purpose of getting output for debugging.
  */
  friend ostream &operator<<(ostream &, const properties &);

  /*!
  @brief getting a value for a key

  @param key the key for which the value should be returned
  @param default_val contains the value to be returned (default NULL) in case the key is not part of the properties
  @param cloneValue if true, a copy of the value is returnde, otherwise a pointer to the value in the properties

  @return returns the value for the key, if it was found, otherwise the value in default_val
  */
  string *get(const string &key, string *default_val = nullptr, bool cloneValue = true);

  /*!
  @brief setting a value for a key

  This method is setting/changing the given value for the given key, additionally it is setting the member saved = false

  @param key contains the key for which the given value is to be stored
  @param value contains the value to be stored for the given key
  */
  void put(const string &key, const string &val);

  /*!
  @brief deleting the key value pair from the properties

  This method is deleting the entry for the given key, additionally it is setting the member saved = false

  @param key contains the key for which the properties-entry is to be deleted
  */
  void remove(const string &key);

  /*!
  This method is saving te properties in the right format.  If the properties file is in read only mode and the
  current user has the privilege to change this mode, it will be set to read/write for this user before the file
  is saved.  After the properties are saved, the file will be set to read only for the given user and all other
  users will have no rights for reading or writing on this property file (storing account credentials unencrypted).

  @throws file_exception if the user has no privilege to change the mode of the property file or if the
  saving of the file fails.
  */
  void save();

  /*!
  @brief getter for saved
  @return true if the properties need to be saved, otherwise false (have been changed since reading/last save)
  */
  bool isSaved();

  /*!
  @brief setter for file name
  @param fileName contains the file name for the properties
  */
  void set_file(const string &fileName);

  /*!
  @brief Converts the relative file name to a full path name

  Converts the given file name in a full file name with path, if it was found

  @param file_name contains a relative or a file name with path

  @return file name with path
  */
  static const string get_full_file_name(const string &file_name);
};

#endif //SEALER_PROPERTIES_H
