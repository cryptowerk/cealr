#ifndef _MACARON_BASE64_H_
#define _MACARON_BASE64_H_

/**
 * The MIT License (MIT)
 * Copyright (c) 2016 tomykaira
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <string>
#include <vector>

using namespace std;

class base64_exception : public exception
{
private:
  runtime_error _what;

public:
  base64_exception(const string &file, const int line, const string &errStr) : _what(
      ("" + file + ":" + to_string(line) + ": " + errStr).c_str()) {}

  const char *what()
  {
    return _what.what();
  }
};

class base64 {
public:
  static string encode(const vector<char> &data)
  {
    static constexpr const char *binary2ascii = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t in_len = data.size();

    size_t out_len = 4 * ((in_len + 2) / 3);
    string ret(out_len, '\0');
    size_t i;
    char *p = const_cast<char *>(ret.c_str());

    for (i = 0; i < in_len - 2; i += 3)
    {
      *p++ = binary2ascii[(data[i] >> 2) & 0x3F];
      *p++ = binary2ascii[((data[i] & 0x3) << 4) | ((data[i + 1] & 0xF0) >> 4)];
      *p++ = binary2ascii[((data[i + 1] & 0xF) << 2) | ((data[i + 2] & 0xC0) >> 6)];
      *p++ = binary2ascii[data[i + 2] & 0x3F];
    }
    if (i < in_len)
    {
      *p++ = binary2ascii[(data[i] >> 2) & 0x3F];
      if (i == (in_len - 1))
      {
        *p++ = binary2ascii[((data[i] & 0x3) << 4)];
        *p++ = '=';
      }
      else
      {
        *p++ = binary2ascii[((data[i] & 0x3) << 4) | ((data[i + 1] & 0xF0) >> 4)];
        *p++ = binary2ascii[((data[i + 1] & 0xF) << 2)];
      }
      *p++ = '=';
    }

    return ret;
  }

  static void replace(string &input, const string &find, const string &repl)
  {
    size_t flen = find.length();
    size_t rlen = repl.length();
    for (size_t index = 0; ((index=input.find(find, index)) != string::npos);)
    {
      input.replace(index, flen, repl);
      index += rlen;
    }
  }

  static vector<char> *decode(const string& rawInput)
  {
    string input = rawInput;
    replace(input, "\r", "");
    replace(input, "\n", "");
    replace(input, " ", "");
    static constexpr unsigned char ascii2binary[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3E, 0xff, 0xff, 0xff, 0x3F,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff,
        0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    size_t in_len = input.size();
    if (in_len & 0x03){
      throw base64_exception(__FILE__, __LINE__, "Size of string to be decoded must be a multiple of 4");
    }

    size_t out_len = (in_len / 4) * 3;
    if (input[in_len - 1] == '=')
    {
      out_len--;
    }
    if (input[in_len - 2] == '=')
    {
      out_len--;
    }
    auto out= new vector<char>(out_len, 0);
    size_t i = 0, j = 0;
    while (i < in_len)
    {
      int ishift = 18;
      uint32_t triple = 0;
      while (ishift>=0)
      {
        char &c = input[i++];
        uint32_t _64bitVal = ascii2binary[static_cast<int>(c)];
        if (_64bitVal==0xff){
          throw base64_exception(__FILE__, __LINE__, "Character \'"+string(1,c)+"\' is not valid supported in this base 64 implementation.");
        }
        triple |= _64bitVal << ishift;
        ishift -= 6;
      }
      int oshift = 16;
      while (oshift>=0 && j < out_len)
      {
        out->at(j++) = (char) (triple >> oshift);
        oshift -= 8;
      }
    }
    return out;
  }
};

#endif /* _MACARON_BASE64_H_ */
