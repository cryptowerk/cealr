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

#include "file_util.h"
#include <openssl/sha.h>

bool dir_exists(const string &path)
{
  struct stat inf{};
  if (stat(path.c_str(), &inf) != 0)
  {
    return false;
  }
  return (inf.st_mode & S_IFDIR) != 0;
}

bool file_exists(const string &file)
{
  struct stat inf{};
  if (stat(file.c_str(), &inf) != 0)
  {
    return false;
  }
  return (inf.st_mode & S_IFDIR) == 0;
}

string *super_path(const string path)
{
  unsigned long pos = path.find_last_of(PATH_SEPARATOR);
  return (pos == string::npos) ? nullptr : new string(path.substr(0, pos));
}

bool mkdirs(const std::string &path)
{
  bool success = dir_exists(path);

  if (!success)
  {
    string *sSuperPath = super_path(path);
    if (sSuperPath != nullptr)
    {
      success = mkdirs(*sSuperPath);
      delete sSuperPath;
      if (success)
      {
        mkdir(path.c_str()
#ifndef _WIN32
            , 0755
#endif
        );
        success = dir_exists(path);
      }
    }
  }
  return success;
}


string *file_name_without_path(const string path)
{
  unsigned long pos = path.find_last_of(PATH_SEPARATOR);
  return new string((pos == string::npos) ? path : path.substr(pos + 1));
}


mode_t get_file_permissions(const string path)
{
  struct stat attributes{};
  mode_t attr = 0;

  if (stat(path.c_str(), &attributes) >= 0)
  {
    attr = attributes.st_mode;
  }
  else
  {
    cerr << "File Error Message = " << strerror(errno) << endl;
  }

  return attr;
}

mode_t set_file_permissions(const string path, const mode_t attrs)
{
  mode_t attr1 = 0;
  if (chmod(path.c_str(), attrs) >= 0)
  {
    attr1 = get_file_permissions(path);
  }
  else
  {
    cerr << "File Error Message = " << strerror(errno) << endl;
  }

  return attr1;
}

string to_hex(const unsigned char *data, const size_t size)
{
  stringstream buf;
  for (int i = 0; i < size; i++)
  {
    buf << hex << setw(2) << setfill('0') << (int) data[i];
  }

  return buf.str();
}

char get_single_character_answer(const string &question, const set<char> valid_answers, const char default_answer)
{
  int c;
  bool ok;
  do
  {
    cout << question;
    cin.clear();
    string input;
    if (isatty(fileno(stdin)))
    {
      static struct termios currentTerminal, singleCharTerminal;
      tcgetattr(STDIN_FILENO, &currentTerminal);
      singleCharTerminal = currentTerminal;
      singleCharTerminal.c_lflag &= ~(ICANON);
      tcsetattr(STDIN_FILENO, TCSANOW, &singleCharTerminal);
      c = getchar();
      fflush(stdout);
      tcsetattr(STDIN_FILENO, TCSANOW, &currentTerminal);
    }
    else
    {
      getline(cin, input);
      c = input[0];
    }

    c = toupper(c);
    if (c == '\n' || c == 0)
    {
      c = default_answer;
    }
    else
    {
      cout << endl;
    }
    if (!(ok = (bool) valid_answers.count((char) c)))
    {
      cout << "Invalid answer, please try again" << endl;
    }
  } while (!ok);
  return (char) c;
}

string *get_string_matching(const string &question, regex regexp)
{
  bool ok;
  string input;
  do
  {
    cout << question;
    cin.clear();
    getline(cin, input);
    input = trim(input);
    smatch m;
    ok = regex_match(input, m, regexp);
    if (!ok)
    {
      cout << "Invalid answer, please try again" << endl;
    }
  } while (!ok);
  return new string(input);
}

string *get_password(const string &question, int min_length, int min_digits, int min_small, int min_caps, string noTtyError)
{
  bool ok = false;
  string input;
  do
  {
    if (isatty(fileno(stdin)))
    {
      cin.clear();
      input = getpass(question.c_str());
    }
    else
    {
      cerr << noTtyError;
      exit(1);
    }
    unsigned long length = input.length();
    if (length < min_length)
    {
      cout << "The password is not long enough: " << endl;
    }
    else
    {
      int digits, small, caps;
      digits = small = caps = 0;
      for (unsigned long i = 0; i < length; i++)
      {
        char c = input[i];
        if (c >= '0' && c <= '9')
        {
          digits++;
        }
        if (isupper(c))
        {
          small++;
        }
        if (isupper(c))
        {
          caps++;
        }
      }
      if (digits < min_digits)
      {
        cout << "The needs at least " << min_digits << " digits." << endl;
      }
      else if (small < min_small)
      {
        cout << "The needs at least " << min_small << " small letters." << endl;
      }
      else if (caps < min_caps)
      {
        cout << "The needs at least " << min_caps << " capital letters." << endl;
      }
      else
      {
        ok = true;
      }
    }
  } while (!ok);
  return new string(input);
}

string *get_opt_str(const string &question)
{
  string input;
  cout << question;
  cin.clear();
  getline(cin, input);
  input = trim(input);
  return (input[0]) == 0 ? nullptr : new string(input);
}

string format_time(time_t timestamp, string format)
{
  struct tm *time;
  char time_str[40];
  const time_t epoch = timestamp / 1000;
  time = localtime(&epoch);
  strftime(time_str, sizeof(time_str), format.c_str(), time);
  return string(time_str);
}


string trim(const string str)
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

int hex_digit_val(const char ch)
{
  const auto l_ch = tolower(ch);
  return isdigit(l_ch) ? l_ch - '0' : l_ch - 'a' + 10;
}

vector<char> from_hex(const string &hex)
{
  const auto len = hex.size() / 2;
  vector<char> ret = vector<char>(len, 0);
  for (int i = 0, j=0; i < len; i++)
  {
    const auto raw = hex_digit_val(hex[j++]) << 4;
    ret[i] = (char) (raw | hex_digit_val(hex[j++]));
  }

  return ret;
}

string getHashAsHex(istream &is)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  return to_hex(getHash(is, hash), SHA256_DIGEST_LENGTH);
}

unsigned char *getHash(istream &is, unsigned char *md)
{
  string *hash_hex;
  SHA256_CTX sha256_ctx;
  SHA256_Init(&sha256_ctx);
  is.unsetf(ios_base::skipws);
  is.seekg(0, ios_base::end);
  auto size = (unsigned long) is.tellg();
  is.seekg(0, ios_base::beg);

  // reserve capacity
  unsigned long buf_size = (size < MAX_BUFFER_SIZE) ? size : MAX_BUFFER_SIZE;
  char buffer[buf_size];
  // read data
  unsigned long ptr = buf_size; // init with ptr after first read
  do
  {
    is.read(buffer, buf_size);
    SHA256_Update(&sha256_ctx, &buffer, buf_size);
    // since read does not return how many bytes are read, we have to keep track ourselves
    if ((ptr += buf_size) > size)
    {
      buf_size -= ptr - size;
      ptr = size;
    }
    // is.eof() is only true if we read beyond eof. We are keeping track of the remaining bytes to read and read
    // never more than available, so eof is never triggered and we have to exit based on buf_size==0
  } while (buf_size);
  SHA256_Final(md, &sha256_ctx);

  return md;
}

string *get_env_str(const string &env_key)
{
  string *envStr = nullptr;
  char *envPwd = getenv(env_key.c_str());
  if (envPwd)
  {
    envStr = new string(envPwd);
  }
  return envStr;
}
