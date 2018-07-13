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

class FileException: public exception {
private:
    string *_file;
public:
    FileException(const string &file);

    virtual const char* what();
};

class Properties: public map<string,string> {
private:
    string sFile;
    bool saved;
public:
    Properties(const string&);
    Properties();
    ~Properties();
    static string trim(const string str);

    void readFromFile();

    const string &getFile() const;

    bool operator==(const Properties &) const;

    bool operator!=(const Properties &) const;

    friend ostream &operator<<(ostream &, const Properties &);

    void save() throw(FileException);
    bool isSaved();

    void setFile(const string &fileName);

    static const string getFullFileName(const string &basic_string);
};

#endif //SEALER_PROPERTIES_H
