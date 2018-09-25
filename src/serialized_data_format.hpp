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

#ifndef CEALR_SERIALIZED_DATA_FORMAT_H
#define CEALR_SERIALIZED_DATA_FORMAT_H

#include <iostream>
#include <string>
#include <list>
#include <vector>
#include <sstream>
#include <map>

using namespace std;

#define currentVersion 20

//class sdf_ostream;

//class Writable
//{
//public:
//  virtual void write(ostream &os) = 0;
//};

// class template for reader (ideally replace with polymorphic lambdas in C++ 14 and above)
template <class T>
class Reader {
public:
  virtual T read() = 0;
};

class io_error : public exception
{
private:
  runtime_error _what;

public:
  io_error(const string &file, const int line, const string &errStr) : _what(
      ("" + file + ":" + to_string(line) + ": " + errStr).c_str()) {}

  const char *what()
  {
    return _what.what();
  }
};


class int_istream : public streambuf
{
public:
  explicit int_istream(vector<char> *data) : streambuf()
  {
    char *gbeg = data->begin().base();
    setg(gbeg, gbeg, data->end().base());
  }

  streamsize read_int8buf(void *buff, size_t offset, streamsize length)
  {
    return xsgetn(((char *) buff) + offset, length);
  }

  int read_int8()
  {
    return sbumpc();
  }

  short read_int16()
  {
    const auto c_h = sbumpc();
    const auto c_l = sbumpc();
    return (short) ((c_h << 8) | c_l);
  }

  int read_int32()
  {
    const auto c_hh = sbumpc();
    const auto c_hl = sbumpc();
    const auto c_lh = sbumpc();
    const auto c_ll = sbumpc();
    return ((c_hh << 24) | (c_hl << 16) | (c_lh << 8) | c_ll);
  }
};

typedef enum compatibility
{
  Default, SuppressReadingOfHeader, PermitPre5Header
} _compatibility;

class sdf_istream
{

private:
  int_istream *inBase;
  int storedVersion;

  int readByteForInt()
  {
    int b = inBase->read_int8();
    if (b < 0)
    {
      throw io_error(__FILE__, __LINE__, "Premature end of data while reading an integer.");
    }
    return b;
  }

public:
  explicit sdf_istream(int_istream *_inBase, _compatibility compatibility)
  {
    inBase = _inBase;
    if (compatibility != _compatibility::SuppressReadingOfHeader)
    {
      readHeader(compatibility == _compatibility::PermitPre5Header);
    }
    else
    {
      storedVersion = 1;
    }
  }

  explicit sdf_istream(vector<char> *in, _compatibility compatibility)
  {
    inBase = new int_istream(in);
    if (compatibility != _compatibility::SuppressReadingOfHeader)
    {
      readHeader(compatibility == _compatibility::PermitPre5Header);
    }
    else
    {
      storedVersion = 1;
    }
  }

  long readInt()
  {
    long v = 0;
    if (supports(13))
    {
      int shift = 0;
      int b = readByteForInt();

      bool isNegative = (b & (1 << 6)) != 0;
      v |= ((long) (b & 0x3F)) << shift;
      shift += 6;

      for (;; shift += 7)
      {
        if ((b & 0x80) == 0)
        {
          break;
        }
        b = readByteForInt();
        v |= ((long) (b & 0x7F)) << shift;
      }

      if (isNegative)
      {
        v = -v;
      }
    }
    else if (supports(5))
    {
      for (int shift = 0;; shift += 7)
      {
        int b = readByteForInt();
        v |= ((long) (b & 0x7F)) << shift;
        if ((b & 0x80) == 0)
        {
          break;
        }
      }
    }
    else
    {
      vector<char> buf(4, 0);
      readRaw(&buf[0], 4);
      int_istream bis(&buf);
      v = bis.read_int32();
    }

    return v;
  }

  bool supports(int minVersion)
  {
    return storedVersion >= minVersion;
  }

  //public sdf_istream(istream inBase) throws io_error {
  //  this(inBase,false);
  //}

  void readHeader(bool permitPre5Header)
  {
    storedVersion = 5; // make subsequent read_int32() use the new input format
    storedVersion = (int) readInt();

    if (permitPre5Header)
    {
      if (storedVersion == 0)
      {
        vector<char> oldStyleVersionRaw(2,0);
        readRaw(&oldStyleVersionRaw[0], (size_t)1, static_cast<int>(oldStyleVersionRaw.size() - 1));
        int_istream in(&oldStyleVersionRaw);
        int oldStyleVersion = in.read_int16();
        if (oldStyleVersion > 4)
        {
          stringstream str;
          str << "Old style version prefix has only been supported up to version 4 but is " << oldStyleVersion;
          throw io_error(__FILE__, __LINE__, str.str());
        }
        storedVersion = oldStyleVersion;
      }
    }

    if (!(storedVersion >= 1 /* min. supported version */ &&
          storedVersion <= currentVersion /* max. supported version */))
    {
      stringstream m;
      m << "Cannot process input stream of version " << storedVersion << ", highest currently known version is " << currentVersion;
      throw io_error(__FILE__, __LINE__, m.str());
    }
  }

  void readRaw(void *b, int len) {
      readRaw(b, 0, len);
  }

  void readRaw(void *b, size_t offset, int length)
  {
    for (int numRead = 0; numRead < length;)
    {
      streamsize got = inBase->read_int8buf(b, (size_t) (offset + numRead), (streamsize) length - numRead);
      if (got < 0)
      {
        stringstream m;
        m << "Cannot fully read a byte array, expected " << length << " bytes but only could read " << numRead << ".";
        throw io_error(__FILE__, __LINE__, m.str());
      }
      else if (got > 0)
      {
        numRead += got;
      }
    }
  }

  // todo implement read_char_vector(int len) and replace hashes by vector<unsigned char>
  vector<unsigned char> *read_char_vector(unsigned long len)
  {
    auto data = new vector<unsigned char>(len);

    for_each(istreambuf_iterator<char>(inBase), //todo correct iterator (current pointer in inBase)
             istreambuf_iterator<char>(),       //todo correct iterator (last character to be copied from inBase)
             [data](const unsigned char c)
             {
               data->push_back(c);
             });

    return data;
  }

  string *readString()
  {
    auto length= static_cast<int>(readInt());
    char textRaw[length+1];
    readRaw(textRaw, length);
    textRaw[length] = '\0';
    return new string(textRaw);
  }

  bool readBoolean()
  {
    return readByte() != 0;
  }

  bool *readOptBoolean()
  {
    return readBoolean() ? new bool(readBoolean()) : nullptr;
  }


  int *readOptInt()
  {
    return readBoolean() ? new int(readInt()) : nullptr;
  }

  char readByte()
  {
    int b = inBase->read_int8();

    return static_cast<char>(b);
  }

  template <class T>
  list<T> *readList(Reader<T> reader)
  {
    auto lst = new list<T>();
    long length = readInt();
    for (long i=0;i<length;i++)
    {
      lst->push_back(reader.read());
    }
    return lst;
  }

  template <class T>
  list<T> *readOptList(Reader<T> &reader)
  {
      return readBoolean()? readList(reader):nullptr;
  }

  vector<char> *readByteBlock()
  {
    auto length = static_cast<unsigned long>(readInt());
    char buf[length];
    readRaw(buf, static_cast<int>(length));
    return new vector<char>(buf, buf+length);
  }

  string *readOptString()
  {
      return readBoolean()? new string(*readString()):nullptr;
  }

  long readDate()
  {
    return readInt();
  }

  int *readOptDate()
  {
      return readBoolean()?new int(readDate()):nullptr;
  }

  template <class T>
  T readOpt(Reader<T> &reader)
  {
    return readBoolean()? reader.read():nullptr;
  }

  vector<char> *readOptByteBlock()
  {
    return readBoolean() ? readByteBlock() : nullptr;
  }

  map<string, vector<char>> *readMap()
  {
    auto map = new ::map<string, vector<char>>();
    long length = readInt();
    for (long i = 0; i < length; i++)
    {
      string *key = readString();
      vector<char> *value = readByteBlock();
      map->insert(pair<string, vector<char>>(*key, *value));
      delete key;
      delete value;
    }
    return map;
  }

//  Pair<?, ?> readPair(Class<?> aClass, Class<?> bClass){
//    Object a = readObject(aClass, nullptr);
//    Object b = readObject(bClass, nullptr);
//    return new Pair<>(a, b);
//  }

//  Object readObject(Class<?> clazz, Reader<?> optReader) {
//    if (clazz == String.class)
//    return readString();
//    else if (clazz == Boolean.class || clazz == bool.TYPE)
//    return readBoolean();
//    else if (clazz == Long.class || clazz == Long.TYPE)
//    return read_int32();
//    else if (clazz == Integer.class || clazz == Integer.TYPE)
//    return Integer.valueOf((int) read_int32());
//    //else if (clazz==Pair.class)
//    //  return readPair(aClass,bClass);
//    else if (clazz == byte[].class)
//    return readByteBlock();
//    else if (Util.doesImplement(clazz, Readable.class)) {
//      try
//      {
//        Constructor< ?> constructor = clazz.getConstructor(sdf_istream.
//        class);
//        Readable obj = (Readable) constructor.newInstance(this);
//        return obj;
//      } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | IllegalArgumentException |
//                                       InvocationTargetException
//      e) {
//        throw io_error(__FILE__, __LINE__, e);
//      }
//    }
//    else if (clazz == List.class /*|| clazz==Set.class*/) {
//      if (optReader == nullptr)
//      {
//        throw io_error(__FILE__, __LINE__, "List object requested but reader not set.");
//      }
//      return readList(optReader);
//    }
//    else
//    throw io_error(__FILE__, __LINE__, "Cannot read object of class " + clazz.getName());
//  }

//  Object readOptObject(Class<?> clazz, Reader<?> optReader)
//  {
//      return readBoolean()? readObject(clazz, optReader):nullptr;
//  }
};

#endif //CEALR_SERIALIZED_DATA_FORMAT_H
