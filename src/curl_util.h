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

#ifndef CEALR_CURLUTIL_H
#define CEALR_CURLUTIL_H

#include <iostream>
#include <string>
#include <curl/curl.h>
//#include "json.h"
#include <nlohmann/json.hpp>

// for convenience
using json = nlohmann::json;

using namespace std;

/*!
@brief CURL helper class

Enables simplified HTTP requests
*/
class curl_util
{
private:
  CURL *curl;
  bool verbose;
  string sUrl;
  string *returnData;
  CURLcode returnCode;
  struct curl_slist *headers;

  /*!
  @brief common method for all HTTP requests

  @return Server response
  */
  string *_request();

public:
  curl_util();

  /*!
  @brief Constructor with URL only

  @param url contains the URL to be requested
  */
  explicit curl_util(string url);

  /*!
  @brief Constructor with URL and verbose flag

  @param url contains the URL to be requested
  @param bVerbose is true when output to cout is requested for debugging; otherwise false
  */
  curl_util(string url, bool bVerbose);

  ~curl_util();

  /*!
  @brief Setter for URL

  @param url contains the URL to be requested
  */
  void setUrl(const string &url);

  /*!
  @brief Method to add a header field of the request

  @param Header field in format "<header name>: <value>"
  */
  void addHeader(const string &headerField);

  /*!
  @brief Setter for verbose flag

  @param bVerbose is true when output to cout is requested for debugging; otherwise false
  */
  void setVerbose(bool bVerbose);

  /*!
  @brief method for GET request

  Performs a HTTP GET request to the URL and with the header that is specified in this object

  @return the response from the server
  */
  string *get();

  /*!
  @brief method for POST request

  Performs a HTTP POST request to the URL and with the header that is specified in this object and with the post body from parameter data.

  @param data contains the body for the POST request to be performed.

  @return the response from the server
  */
  string *post(const string &data);

  /*!
  @brief method for POST request

  Performs a HTTP POST request to the URL from the parameter URL, with the header that is specified in this object and with the post body from parameter data.

  @param url contains the url for the POST request to be performed.
  @param data contains the body for the POST request to be performed.

  @return the response from the server
  */
  string *post(const string &url, const string &data);

  /*!
  @brief method for POST request with JSON

  Performs a HTTP POST request to the URL from the parameter URL, with the header that is specified in this object and with the post body as a JSON formatted string from parameter json.

  @param url contains the url for the POST request to be performed.
  @param json contains the json object for the body of the POST request.

  @return the response from the server
  */
  string *post(const string &url, const json &json);

  /*!
  @brief method for POST request with JSON

  Performs a HTTP POST request  to the URL and with the header that is specified in this object and with the post body as a JSON formatted string from parameter json.

  @param json contains the json object for the body of the POST request.

  @return the response from the server
  */
  string *post(const json &json);

  /*!
  @brief method for GET request

  Performs a HTTP GET request to the URL from the parameter URL and with the header that is specified in this object.

  @param url contains the url for the GET request to be performed.

  @return the response from the server
  */
  string *get(string &url);
};


#endif //CEALR_CURLUTIL_H
