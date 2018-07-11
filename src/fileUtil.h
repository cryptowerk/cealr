//
// Created by Olaf Zumpe on 7/11/18.
//

#ifndef CEALR_FILEUTIL_H
#define CEALR_FILEUTIL_H
#include <string>
#include <sys/stat.h>
//#include <errno.h>    // errno, ENOENT, EEXIST
#ifdef _WIN32
#include <direct.h>   // _mkdir
#define stat _stat;
#define S_IFDIR _S_IFDIR
#define mkdir _mkdir
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

using namespace std;

bool dirExists(const string& path);
string *superPath(const string path);
string *fileNameWithoutPath(const string path);

bool mkdirs(const std::string& path);


#endif //CEALR_FILEUTIL_H
