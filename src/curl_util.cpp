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

#include "curl_util.h"
#include <utility>

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t bytes = size * nmemb;
  ((string *) userp)->append((char *) contents, bytes);
  return bytes;
}

curl_util::curl_util(string url, bool bVerbose)
{
  setUrl(url);
  setVerbose(bVerbose);
  headers = nullptr;
  returnData = new string();
  curl = curl_easy_init();
  //todo curlUtilException
  if (!curl)
  {
    cerr << "Cannot initialize curl." << endl;
    exit(1);
  }

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, returnData);
}

curl_util::curl_util(string url) : curl_util(std::move(url), false) {}

curl_util::curl_util() : curl_util(nullptr, false) {}

curl_util::~curl_util()
{
  if (headers)
  {
    curl_slist_free_all(headers);
  }
  curl_global_cleanup();
  delete returnData;
}

string *curl_util::get()
{
  if (!curl)
  {
  }
  curl_easy_setopt(curl, CURLOPT_URL, sUrl.c_str());
  return _request();
}

string *curl_util::get(string &url)
{
  setUrl(url);
  return get();
}

string *curl_util::post(const string &url, const string &data)
{
  setUrl(url);
  return post(data);
}

string *curl_util::post(const string &data)
{
  if (verbose)
  {
    cout << "URL:  " << sUrl << endl
         << "Data: " << data << endl;
  }
  string readBuffer;
  curl_easy_setopt(curl, CURLOPT_URL, sUrl.c_str());
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) data.size());
  return _request();
}

void curl_util::addHeader(const string &headerField)
{
  headers = curl_slist_append(headers, headerField.c_str());
}

string *curl_util::post(const json &json)
{
  stringstream sJson;
  sJson << json;
  addHeader("Content-Type: application/json");
  return post(sJson.str());
}

string *curl_util::post(const string &url, const json &json)
{
  setUrl(url);
  return post(json);
}

string *curl_util::_request()
{
  bool redirecting;
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  do
  {
    redirecting = false;
    returnCode = curl_easy_perform(curl);
    if (returnCode != CURLE_OK)
    {
      //todo curlUtilException
      cerr << "curl_easy_perform() failed: " << curl_easy_strerror(returnCode) << endl;
//            exit(1);
    }
    if (verbose)
    {
      cout << returnData->size() << " bytes retrieved" << endl
           << *returnData << endl;
    }

    long response_code;
    returnCode = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (verbose)
    {
      cout << "response code " << returnCode << endl;
    }
    if (returnCode == CURLE_OK && response_code == 200)
    {
    }
    else if (returnCode == CURLE_OK && response_code / 100 == 3)
    {
      char *location;
      returnCode = curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &location);
      if (returnCode == CURLE_OK && location)
      {
        // location is absolute
        if (verbose)
        {
          cout << "Redirected to: " << location << endl;
        }
        curl_easy_setopt(curl, CURLOPT_URL, location);
        redirecting = true;
      }
    }
    else
    {
      //todo curlUtilException
      cerr << "Unexpected response from server: " << *returnData << endl;
      exit(1);
    }
  } while (redirecting);
  curl_easy_cleanup(curl);

  return returnData;
}

void curl_util::setUrl(const string &url)
{
  sUrl = url;
}

void curl_util::setVerbose(const bool bVerbose)
{
  verbose = bVerbose;
}
