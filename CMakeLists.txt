cmake_minimum_required(VERSION 3.6)
project(cealr)

set(CMAKE_CXX_STANDARD 14)
cmake_policy(SET CMP0060 NEW)

set(SOURCE_FILES src/cealr.cpp src/cealr.h src/properties.cpp src/properties.h src/curl_util.cpp src/curl_util.h src/file_util.cpp src/file_util.h src/open_pgp.cpp src/open_pgp.h src/smart_stamp.cpp src/smart_stamp.h src/serialized_data_format.hpp src/message_digest.cpp src/message_digest.h src/base64.h)
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(OPENSSL_USE_STATIC_LIBS TRUE)
set(NLOHMANN_JSON_DIR ${CMAKE_CURRENT_BINARY_DIR}/include/nlohmann)

if(NOT EXISTS ${NLOHMANN_JSON_DIR})
  file(MAKE_DIRECTORY ${NLOHMANN_JSON_DIR})
  file(DOWNLOAD https://github.com/nlohmann/json/releases/download/v3.1.2/json.hpp ${NLOHMANN_JSON_DIR}/json.hpp)
endif()
#find_package(nlohmann_json CONFIG REQUIRED)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR})
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Gpgme REQUIRED)

INCLUDE_DIRECTORIES(${CURL_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/include ${GPGME_INCLUDES})
SET(LIBS ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES})
add_library(curl UNKNOWN IMPORTED)
add_library(openssl UNKNOWN IMPORTED)
set_property(TARGET curl PROPERTY IMPORTED_LOCATION "${CURL_LIBRARIES}")

IF(CMAKE_BUILD_TYPE MATCHES Debug)
  message("Debug build.")
ELSEIF(CMAKE_BUILD_TYPE MATCHES Release)
  message("Release build.")
ELSE()
  message("Some other build type.")
ENDIF()

add_executable(cealr ${SOURCE_FILES})
target_link_libraries(cealr ssl crypto curl gpgme)
