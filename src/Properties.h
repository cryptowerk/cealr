//
// Created by Olaf Zumpe on 6/6/18.
//

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
