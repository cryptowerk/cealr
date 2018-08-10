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

#include "Properties.h"
#include "fileUtil.h"

FileException::FileException(const string &file) : errMsg(("Error on opening file \"" + (file) + "\"").c_str()) {}

const char *FileException::what() {
    return errMsg.what();
}

//class Properties: public map<string,string> {
Properties::Properties(const string &fileName) {
    setFile(fileName);
    readFromFile();
}

Properties::Properties() : Properties(DEFAULT_PROPERTIES){};

//class Properties: public map<string,string> {
void Properties::setFile(const string &fileName) {
    sFile = getFullFileName(fileName);
}

const string Properties::getFullFileName(const string &fileName) {
    string fullName = fileName;
    if ((unsigned char) fullName[0] == '~'){
        char *home = getenv("HOME");
        if (home) {
            fullName = home+fullName.erase(0, 1);
        }
    }

    return fullName;
}

void Properties::readFromFile() {
    ifstream ifs(sFile.c_str());
    if (ifs.is_open()) {
        saved = true;
        while (ifs/*.good()*/) {
            ifs >> ws;
            string line;
            string key, value;
            getline(ifs, key, '=');
            getline(ifs, value);
            key = trim(key);
            value = trim(value);
            if (!key.empty() && key[0] != '#' && !value.empty()) {
                (*this)[key] = value;
            }
        };
        ifs.close();
    } else {
        saved = false;
    }
}

//string Properties::trim(basic_string<char, char_traits<char>, allocator<char>> str) {
string Properties::trim(const string str) {
    string s = str;
    unsigned long p;
    while ((p = s.length()) > 0 && (unsigned char) s[p - 1] <= ' ')
        s.resize(p - 1);
    while (s.length() > 0 && (unsigned char) s[0] <= ' ')
        s.erase(0, 1);
    return s;
}

void Properties::save() {
    string *pth = superPath(sFile);
    if (pth!= nullptr) {
        mkdirs(*pth);
        setFilePermissions(*pth, S_IRUSR|S_IWUSR|S_IXUSR );
        if (fileExists(sFile)) {
            setFilePermissions(sFile, S_IRUSR | S_IWUSR);
        }
        ofstream ofs((sFile).c_str(), std::ofstream::out);
        if (ofs.fail()) {
            throw FileException(getFile());
        }
        for (const auto &p : *this) {
            ofs << p.first << " = " << p.second << endl;
        }
        ofs.flush();
        ofs.close();
        saved = true;
        //protect with read for user (no prev for group and other)
        setFilePermissions( sFile, S_IRUSR );
        setFilePermissions(*pth, S_IRUSR|S_IXUSR );
    }
}

bool Properties::operator==(const Properties &properties) const {
    return static_cast<const map<string, string> &>(*this) == static_cast<const map<string, string> &>(properties) &&
           sFile == properties.sFile;
}

bool Properties::operator!=(const Properties &properties) const {
    return !(properties == *this);
}

const string &Properties::getFile() const {
    return sFile;
}

ostream &operator<<(ostream &os, const Properties &properties) {
    os << "Properties file: " << properties.sFile << endl;
    for (const auto &p : properties) {
        os << "properties[" << p.first << "] = " << p.second << endl;
    }
    return os;
}

bool Properties::isSaved() {
    return saved;
}

