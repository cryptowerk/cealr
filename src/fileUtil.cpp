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

bool dirExists(const std::string &path) {
    struct stat inf;
    if (stat(path.c_str(), &inf) != 0) {
        return false;
    }
    return (inf.st_mode & S_IFDIR) != 0;
}

string *superPath(const string path) {
    unsigned long pos = path.find_last_of(PATH_SEPARATOR);
    return (pos == string::npos) ? NULL : new string(path.substr(0, pos));
}

bool mkdirs(const std::string &path) {
    bool success = dirExists(path);

    if (!success) {
        string *sSuperPath = superPath(path);
        if (sSuperPath != NULL) {
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
    return (pos == string::npos) ? NULL : new string(path.substr(pos + 1));
}

