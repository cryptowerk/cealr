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

class curl_util {
private:
    CURL *curl;
    bool verbose;
    string sUrl;
    string *returnData;
    CURLcode returnCode;
    struct curl_slist *headers;

    string *_request();

public:
    curl_util();

    curl_util(string url);


    curl_util(string url, bool bVerbose);

    ~curl_util();

    void setUrl(const string &url);

    void addHeader(const string &headerField);

    void setVerbose(bool bVerbose);

    string *get();

    string *post(const string &data);

    string *post(const string &url, const string &data);

    string *post(const string &url, const json &json);

    string *post(const json &json);

    string *get(string &url);
};


#endif //CEALR_CURLUTIL_H
