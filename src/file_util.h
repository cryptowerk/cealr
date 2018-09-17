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

/*!
@brief method returns true, if path exists. Otherwise false.

@param path reference to path to be checked for existence.

@return true if path exists, otherwise false
*/
bool dir_exists(const string &path);

/*!
@brief method returns true, if file exists. Otherwise false.

@param file reference to file to be checked for existence.

@return true if file exists, otherwise false
*/
bool file_exists(const string &file);

/*!
@brief get parent path of file or directory

@param path path name of file or directory

@return parent path of given file or directory
*/
string *super_path(string path);

/*!
@brief get file name from full path

@param path to be processed

@return plain file name: last part of the path name
*/
string *file_name_without_path(string path);

/*!
@brief Creates path if or parts of it that are not existing

Creates none, one, multiple or all directories necessary in order to create the full path referenced by parameter path.

@param path references the string that contains the path to be created.

@return true if successful, otherwise false.
*/
bool mkdirs(const string &path);

/*!
@brief get permissions of a file or directory

@param path contains path for which the permissions are to be checked

@return integer with permission bits
*/
mode_t get_file_permissions(string path);

/*!
@brief set permissions for a file or directory

@param path contains path for which the permissions are to be set
@param attrs contains permissions to be set

@return integer with permission bits after manipulation
*/
mode_t set_file_permissions(string path, mode_t attrs);

/*!
@prompts user for password

This method is prompting the user for a password until the typed in password matches the specifications.

@param question contains the print out to prompt user for password
@param min_length specifies the minimum length for the password to be accepted as valid.
@param min_digits specifies the minimum number of digits for the password to be accepted.
@param min_small  specifies the minimum number of small letters for the password to be accepted.
@param min_caps   specifies the minimum number of capital letters for the password to be accepted.
@param noTtyError error to be printed out, if the password input is not possible because it can not be hidden
       nor protected (file as standard input stream)

@return entered password
*/
string *get_password(const string &question, int min_length, int min_digits, int min_small, int min_caps, string noTtyError);

/*!
@brief input string that matches regex

This method prompts and waits for the input of an answer that matches a certain regular expression until the answer is
valid.

@param question contains the string to be print out to prompt for the answer to be typed in (e.g. email address)
@param regexp regular expression that the answer needs to match in order to be accepted.

@return valid typed in answer
*/
string *get_string_matching(const string &question, regex regexp);

/*!
@brief optional input of string

This method prompts and waits for the input of an answer that that can be empty.

@return pointer to the answer that was typed in or NULL, if answer was empty.
*/
string *get_opt_str(const string &question);

/*!
@brief wait for a single character as answer.

@param question references a string with the printout that prompts the user for a single character answer.
@param valid_answers set with valid characters for the answer.
@param default_answer Answer that will be returned, if user presses enter

@return single cahracter answer that the user chose
*/
char get_single_character_answer(const string &question, set<char> valid_answers, char default_answer);

/*!
This method is converting the java timestamp (= unix epoch times 1000ms) (ms since 1970/01/01 12:00am) to a string.

@param timestamp contains the java timestamp (= unix epoch times 1000ms) (ms since 1970/01/01 12:00am)
@param format, see @refitem strftime

@return string with formatted time
*/
string format_time(time_t timestamp, string format);

/*!
@brief returns string without leading and trailing white spaces.

@param str contains a string that may contain leading and trailing white spaces

@return string copied form parameter str without leading and trailing white spaces
*/
string trim(string str);

/*!
@brief converts a hexadecimal digit to its integer vallue

This method interprets the input value as an ASCII character with a hexadecimal digit (0-9, A-F) and returns its
integer value 0-15

@param ch ASCII character may 0-9, a-f or A-F to be interpreted as a hexadecimal digit.

@return value of the given digit (0-15).
*/
int hex_digit_val(char ch);

/*!
@brief Converts character array into hexadecimal string without spaces or line breaks.

 @param data character array to be converted.
 @param size number of characters in the array to be converted

 @return string with hexadecimal interpretation of the given character array.
*/
string to_hex(const unsigned char *data, size_t size);

/*!
@brief hexadecimal string to char vector

This method interprets the given string as sequence of hexadecimal characters and converts them into byte (character)
vector.

@param hex contains the string with hexadecimal ASCII characters

@return vector with bytes that are matching the values of the string, converted from hexadecimal digits
*/
vector<char> from_hex(const string &hex);

/*!
@brief takes an input stream of characters and returns its sha256 hash as hexadecimal string.

@param is input stream to be hashed

@return String with hexadecimal notation of the hash over the input stream.
*/
string getHashAsHex(istream &is);

/*!
@brief returns hash over input stream as array of unsigned characters.

@param is input stream to be hashed.
@param md points to an array of 32 characters tha serves as buffer for the result and will contain the result after the
       hashing operation.

@return the same pointer as in md
*/
unsigned char *getHash(istream &is, unsigned char *md);

/*!
takes the string referenced

@param env_key string with name of an environment variable.

@return value of the environment variable with the name referenced by parameter env_key.
*/
string *get_env_str(const string &env_key);

#endif //CEALR_FILE_UTIL_H
