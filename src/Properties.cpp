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

#include "Properties.h"
#include "file_util.h"

file_exception::file_exception(const string &file) : err_msg(("Error on opening file \"" + (file) + "\"").c_str()) {}

const char *file_exception::what()
{
  return err_msg.what();
}

Properties::Properties(const string &fileName)
{
  set_file(fileName);
  read_from_file();
}

Properties::Properties() : Properties(DEFAULT_PROPERTIES) {};

Properties::~Properties()
{
  if (!saved)
  {
    save();
  }
};

void Properties::set_file(const string &fileName)
{
  file = get_full_file_name(fileName);
}

const string Properties::get_full_file_name(const string &file_name)
{
  string full_name = file_name;
  if ((unsigned char) full_name[0] == '~')
  {
    char *home = getenv("HOME");
    if (home)
    {
      full_name = home + full_name.erase(0, 1);
    }
  }

  return full_name;
}

void Properties::read_from_file()
{
  ifstream ifs(file.c_str());
  if (ifs.is_open())
  {
    saved = true;
    while (ifs/*.good()*/)
    {
      ifs >> ws;
      string line;
      string key, value;
      getline(ifs, key, '=');
      getline(ifs, value);
      key = trim(key);
      value = trim(value);
      if (!key.empty() && key[0] != '#' && !value.empty())
      {
        (*this)[key] = value;
      }
    };
    ifs.close();
  }
  else
  {
    saved = false;
  }
}

string Properties::trim(const string str)
{
  string s = str;
  unsigned long p;
  while ((p = s.length()) > 0 && (unsigned char) s[p - 1] <= ' ')
  {
    s.resize(p - 1);
  }
  while (s.length() > 0 && (unsigned char) s[0] <= ' ')
  {
    s.erase(0, 1);
  }
  return s;
}

void Properties::save()
{
  string *pth = super_path(file);
  if (pth != nullptr)
  {
    mkdirs(*pth);
    set_file_permissions(*pth, S_IRUSR | S_IWUSR | S_IXUSR);
    if (fileExists(file))
    {
      set_file_permissions(file, S_IRUSR | S_IWUSR);
    }
    ofstream ofs((file).c_str(), std::ofstream::out);
    if (ofs.fail())
    {
      throw file_exception(getFile());
    }
    for (const auto &p : *this)
    {
      ofs << p.first << " = " << p.second << endl;
    }
    ofs.flush();
    ofs.close();
    saved = true;
    //protect with read for user (no prev for group and other)
    set_file_permissions(file, S_IRUSR);
    set_file_permissions(*pth, S_IRUSR | S_IXUSR);
  }
}

bool Properties::operator==(const Properties &properties) const
{
  return static_cast<const map<string, string> &>(*this) == static_cast<const map<string, string> &>(properties) &&
         file == properties.file;
}

bool Properties::operator!=(const Properties &properties) const
{
  return !(properties == *this);
}

const string &Properties::getFile() const
{
  return file;
}

ostream &operator<<(ostream &os, const Properties &properties)
{
  os << "Properties file: " << properties.file << endl;
  for (const auto &p : properties)
  {
    os << "Properties[" << p.first << "] = " << p.second << endl;
  }
  return os;
}

string *Properties::get(const string &key, string *default_val, const bool copy)
{
  if (this->count(key))
  {
    return new string((*this)[key]);
  }
  else
  {
    if (default_val && copy)
    {
      return new string(*default_val);
    }
    else
    {
      return const_cast<string*>(default_val);
    }
  }
}

void Properties::put(const string &key, const string &val)
{
  (*this)[key] = val;
  saved = false;
}

void Properties::remove(const string &key)
{
  this->erase(key);
  saved = false;
}

// todo override = operators to reset saved flag

bool Properties::isSaved()
{
  return saved;
}
