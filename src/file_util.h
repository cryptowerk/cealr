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

#ifndef CEALR_FILE_UTIL_H
#define CEALR_FILE_UTIL_H

#ifdef WIN32
// Definiitions to exclude selected header files.

//#define WIN32_LEAN_AND_MEAN

//#define NOATOM
//#define NOCLIPBOARD
//#define NOCOMM
//#define NOCTLMGR
//#define NOCOLOR
//#define NODEFERWINDOWPOS
//#define NODESKTOP
//#define NODRAWTEXT
//#define NOEXTAPI
//#define NOGDICAPMASKS
//#define NOHELP
//#define NOICONS
//#define NOTIME
//#define NOIMM
//#define NOKANJI
//#define NOKERNEL
//#define NOKEYSTATES
//#define NOMCX
//#define NOMEMMGR
//#define NOMENUS
//#define NOMETAFILE
//#define NOMSG
//#define NONCMESSAGES
//#define NOPROFILER
//#define NORASTEROPS
//#define NORESOURCE
//#define NOSCROLL
////#define NOSERVICE		/* Windows NT Services */
//#define NOSHOWWINDOW
//#define NOSOUND
//#define NOSYSCOMMANDS
//#define NOSYSMETRICS
//#define NOSYSPARAMS
//#define NOTEXTMETRIC
//#define NOVIRTUALKEYCODES
//#define NOWH
//#define NOWINDOWSTATION
//#define NOWINMESSAGES
//#define NOWINOFFSETS
//#define NOWINSTYLES
//#define OEMRESOURCE
//
//#include "envirmnt.h"
#include <windows.h>
//#include <tchar.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <malloc.h>
#include <io.h>
#include "support.h"
#include <direct.h>   // _mkdir
#ifdef _MT
#include <process.h>
#endif

#define stat _stat;
#define S_IFDIR _S_IFDIR
#define mkdir _mkdir

typedef int mode_t;
static const mode_t S_ISUID = 0x08000000;           // not relvant
static const mode_t S_ISGID = 0x04000000;           // not relvant
static const mode_t S_ISVTX = 0x02000000;           // not relvant
static const mode_t S_IRUSR = mode_t(_S_IREAD);     // read by user
static const mode_t S_IWUSR = mode_t(_S_IWRITE);    // write by user
static const mode_t S_IXUSR = 0x00400000;           // not relvant

static const mode_t S_IRGRP = mode_t(_S_IREAD);     // read by UGO
static const mode_t S_IWGRP = mode_t(_S_IWRITE);    // write by UGO
static const mode_t S_IXGRP = 0x00080000;           // not relevant
static const mode_t S_IROTH = mode_t(_S_IREAD);     // read by UGO
static const mode_t S_IWOTH = mode_t(_S_IWRITE);    // write by UGO
static const mode_t S_IXOTH = 0x00010000;           // not relevant

#define chmod(path, mode) _chmod(path, (mode & 0x0000ffff))

#if !defined(_Wp64)
#define DWORD_PTR DWORD
#define LONG_PTR LONG
#define INT_PTR INT
#endif

#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#include <string>
#include <sys/stat.h>
//#include <sys/types.h>
//#include <sys/errno.h>
#include <zconf.h>
#include <sys/termios.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <regex>
#include <set>

#endif

using namespace std;

#define MAX_BUFFER_SIZE 0x4000

bool dir_exists(const string &path);

bool fileExists(const string &path);

string *super_path(string path);

string *file_name_without_path(string path);

bool mkdirs(const string &path);

mode_t get_file_permissions(string path);

mode_t set_file_permissions(string path, mode_t attrs);

string *get_password(const string &question, int min_length, int min_digits, int min_small, int min_caps, string noTtyError);

string *get_string_matching(const string &question, regex regexp);

string *get_opt_str(const string &question);

char get_single_character_answer(const string &question, set<char> valid_answers, char default_answer);

string format_time(time_t timestamp, string format);

string trim(string str);

int hex_digit_val(char ch);

string to_hex(const unsigned char *data, size_t size);

vector<char> from_hex(const string &hex);

string getHashAsHex(istream &is);

unsigned char *getHash(istream &is, unsigned char *md);

string *get_env_str(const string &);

#endif //CEALR_FILE_UTIL_H
