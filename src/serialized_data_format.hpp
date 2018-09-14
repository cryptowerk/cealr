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

class IOException : public exception
{
private:
  runtime_error _what;

public:
  IOException(const string &file, const int line, const string &errStr) : _what(
      ("" + file + ":" + to_string(line) + ": " + errStr).c_str()) {}

  const char *what()
  {
    return _what.what();
  }
};


class ByteArrayInputStream : streambuf
{
public:
  explicit ByteArrayInputStream(vector<char> *data) : streambuf()
  {
    char *gbeg = data->begin().base();
    setg(gbeg, gbeg, data->end().base());
  }

  int read()
  {
    return sbumpc();
  }

  streamsize read(void *buff, size_t offset, streamsize length) {
    return xsgetn(((char*)buff)+offset,length);
  }

  int readInt()
  {
      int ch1 = read();
      int ch2 = read();
      int ch3 = read();
      int ch4 = read();

      return ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0));
  }

  short readShort() {
      int ch1 = read();
      int ch2 = read();

      return (short)((ch1 << 8) + (ch2 << 0));
  }
};

typedef enum Compatibility
{
  Default, SuppressReadingOfHeader, PermitPre5Header
} _Compatibility;

class sdf_istream
{

private:
  ByteArrayInputStream *inBase;
  int storedVersion;

  int readByteForInt()
  {
    int b = inBase->read();
    if (b < 0)
    {
      throw IOException(__FILE__, __LINE__, "Premature end of data while reading an integer.");
    }
    return b;
  }

public:
  explicit sdf_istream(ByteArrayInputStream *_inBase, _Compatibility compatibility)
  {
    inBase = _inBase;
    if (compatibility != _Compatibility::SuppressReadingOfHeader)
    {
      readHeader(compatibility == _Compatibility::PermitPre5Header);
    }
    else
    {
      storedVersion = 1;
    }
  }

  explicit sdf_istream(vector<char> *in, _Compatibility compatibility)
  {
    inBase = new ByteArrayInputStream(in);
    if (compatibility != _Compatibility::SuppressReadingOfHeader)
    {
      readHeader(compatibility == _Compatibility::PermitPre5Header);
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
      ByteArrayInputStream bis(&buf);
      v = bis.readInt();
    }

    return v;
  }

  bool supports(int minVersion)
  {
    return storedVersion >= minVersion;
  }

  //public sdf_istream(istream inBase) throws IOException {
  //  this(inBase,false);
  //}

  void readHeader(bool permitPre5Header)
  {
    storedVersion = 5; // make subsequent readInt() use the new input format
    storedVersion = (int) readInt();

    if (permitPre5Header)
    {
      if (storedVersion == 0)
      {
        vector<char> oldStyleVersionRaw(2,0);
        readRaw(&oldStyleVersionRaw[0], (size_t)1, static_cast<int>(oldStyleVersionRaw.size() - 1));
        ByteArrayInputStream in(&oldStyleVersionRaw);
        int oldStyleVersion = in.readShort();
        if (oldStyleVersion > 4)
        {
          stringstream str;
          str << "Old style version prefix has only been supported up to version 4 but is " << oldStyleVersion;
          throw IOException(__FILE__, __LINE__, str.str());
        }
        storedVersion = oldStyleVersion;
      }
    }

    if (!(storedVersion >= 1 /* min. supported version */ &&
          storedVersion <= currentVersion /* max. supported version */))
    {
      stringstream m;
      m << "Cannot process input stream of version " << storedVersion << ", highest currently known version is " << currentVersion;
      throw IOException(__FILE__, __LINE__, m.str());
    }
  }

  void readRaw(void *b, int len) {
      readRaw(b, 0, len);
  }

  void readRaw(void *b, size_t offset, int length)
  {
    for (int numRead = 0; numRead < length;)
    {
      streamsize got = inBase->read(b, (size_t) (offset + numRead), (streamsize) length - numRead);
      if (got < 0)
      {
        stringstream m;
        m << "Cannot fully read a byte array, expected " << length << " bytes but only could read " << numRead << ".";
        throw IOException(__FILE__, __LINE__, m.str());
      }
      else if (got > 0)
      {
        numRead += got;
      }
    }
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


  int *readOptInt() {
      return readBoolean()? new int (readInt()):nullptr;
  }

  char readByte()
  {
      int b=inBase->read();

      return static_cast<char>(b);
  }

//  list<vector<char>> *readByteBlockList()
//  {
//    auto *lst = new list<vector<char>>();
//    long length = readInt();
//    for (long i=0;i<length;i++)
//    {
//      lst->push_back(*readByteBlock());
//    }
//    return lst;
//  }

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
//    return readInt();
//    else if (clazz == Integer.class || clazz == Integer.TYPE)
//    return Integer.valueOf((int) readInt());
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
//        throw IOException(__FILE__, __LINE__, e);
//      }
//    }
//    else if (clazz == List.class /*|| clazz==Set.class*/) {
//      if (optReader == nullptr)
//      {
//        throw IOException(__FILE__, __LINE__, "List object requested but reader not set.");
//      }
//      return readList(optReader);
//    }
//    else
//    throw IOException(__FILE__, __LINE__, "Cannot read object of class " + clazz.getName());
//  }

//  Object readOptObject(Class<?> clazz, Reader<?> optReader)
//  {
//      return readBoolean()? readObject(clazz, optReader):nullptr;
//  }
};

#endif //CEALR_SERIALIZED_DATA_FORMAT_H
