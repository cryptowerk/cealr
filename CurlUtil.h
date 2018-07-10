//
// Created by Olaf Zumpe on 6/17/18.
//

#ifndef CEALR_CURLUTIL_H
#define CEALR_CURLUTIL_H

#include <iostream>
#include <string>
#include <curl/curl.h>
//#include "JSON.h"
#include <nlohmann/json.hpp>

// for convenience
using JSON = nlohmann::json;

using namespace std;

class CurlUtil {
private:
    CURL *curl;
    bool verbose;
    string sUrl;
    string *returnData;
    CURLcode returnCode;
    struct curl_slist *headers;

    string *_request();

public:
    CurlUtil();

    CurlUtil(string url);

    CurlUtil(string, bool);

    ~CurlUtil();

    void setUrl(const string &url);

    void addHeader(const string &headerField);

    void setVerbose(const bool bVerbose);

    string *get();

    string *post(const string &data);

    string *post(const string &url, const string &data);

    string *post(const string &url, const JSON &json);

    string *post(const JSON &json);

    string *get(string &url);
};


#endif //CEALR_CURLUTIL_H
