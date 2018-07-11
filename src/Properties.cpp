//
// Created by Olaf Zumpe on 6/6/18.
//

#include <cursesf.h>
#include "Properties.h"
#include <sys/stat.h> // stat
#include <errno.h>    // errno, ENOENT, EEXIST
#ifdef _WIN32
#include <direct.h>   // _mkdir
#define stat _stat;
#define S_IFDIR _S_IFDIR
#define mkdir _mkdir
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

bool dirExists(const std::string& path) {
    struct stat inf;
    if (stat(path.c_str(), &inf) != 0)
    {
        return false;
    }
    return (inf.st_mode & S_IFDIR) != 0;
}

string *superPath(const string path) {
    unsigned long pos = path.find_last_of(PATH_SEPARATOR);
    return (pos == string::npos) ? NULL : new string(path.substr(0, pos));
}

bool mkdirs(const std::string& path) {
    bool success = dirExists(path);

    if (!success) {
        string *sSuperPath = superPath(path);
        if (sSuperPath!=NULL){
            success = mkdirs(*sSuperPath);
            delete sSuperPath;
            if ( success) {
                mkdir(path.c_str()
#ifndef _WIN32
                        , 0755
#endif
                );
                success = dirExists(path);
            }
        }
    }
    return success;
}

FileException::FileException(const string &file) {
    _file = (string *) &file;
}

const char *FileException::what() {
    return ("Error on opening file \"" + (*_file) + "\"").c_str();
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
    unsigned int p;
    while ((p = s.length()) > 0 && (unsigned char) s[p - 1] <= ' ')
        s.resize(p - 1);
    while (s.length() > 0 && (unsigned char) s[0] <= ' ')
        s.erase(0, 1);
    return s;
}

void Properties::save() throw(FileException){
    string *p = superPath(sFile);
    if (p!=NULL) {
        mkdirs(*p);
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
    }
}

Properties::~Properties() {
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

