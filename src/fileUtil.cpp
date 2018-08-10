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

#include "fileUtil.h"

bool dirExists(const string &path) {
    struct stat inf{};
    if (stat(path.c_str(), &inf) != 0) {
        return false;
    }
    return (inf.st_mode & S_IFDIR) != 0;
}

bool fileExists(const string &path) {
    struct stat inf{};
    if (stat(path.c_str(), &inf) != 0) {
        return false;
    }
    return (inf.st_mode & S_IFDIR) == 0;
}

string *superPath(const string path) {
    unsigned long pos = path.find_last_of(PATH_SEPARATOR);
    return (pos == string::npos) ? nullptr : new string(path.substr(0, pos));
}

bool mkdirs(const std::string &path) {
    bool success = dirExists(path);

    if (!success) {
        string *sSuperPath = superPath(path);
        if (sSuperPath != nullptr) {
            success = mkdirs(*sSuperPath);
            delete sSuperPath;
            if (success) {
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


string *fileNameWithoutPath(const string path) {
    unsigned long pos = path.find_last_of(PATH_SEPARATOR);
    return (pos == string::npos) ? nullptr : new string(path.substr(pos + 1));
}


mode_t getFilePermissions( const string path) {
    struct stat attributes{};
    mode_t attr = 0;

    if (stat(path.c_str(), &attributes) >= 0) {
        attr = attributes.st_mode;
    } else {
        cerr << "File Error Message = " << strerror(errno) << endl;
    }

    return attr;
}

mode_t setFilePermissions( const string path, const mode_t attrs) {
    mode_t attr1 = 0;
    if (chmod(path.c_str(), attrs) >= 0) {
        attr1 = getFilePermissions(path);
    } else {
        cerr << "File Error Message = " << strerror(errno) << endl;
    }

    return attr1;
}
