cmake_minimum_required(VERSION 3.6)
project(cealr)

set(CMAKE_CXX_STANDARD 11)
cmake_policy(SET CMP0060 NEW)

set(SOURCE_FILES cealr.cpp cealr.h Properties.cpp Properties.h CurlUtil.cpp CurlUtil.h)
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(OPENSSL_USE_STATIC_LIBS TRUE)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

INCLUDE_DIRECTORIES(${CURL_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})
SET(LIBS ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES})
add_library(curl UNKNOWN IMPORTED)
add_library(openssl UNKNOWN IMPORTED)
set_property(TARGET curl PROPERTY IMPORTED_LOCATION "${CURL_LIBRARIES}")


add_executable(cealr ${SOURCE_FILES})
target_link_libraries(cealr ssl crypto curl)
