cmake_minimum_required(VERSION 3.6)
project(cealr)

set(CMAKE_CXX_STANDARD 11)
cmake_policy(SET CMP0060 NEW)

set(SOURCE_FILES src/cealr.cpp src/cealr.h src/Properties.cpp src/Properties.h src/CurlUtil.cpp src/CurlUtil.h src/fileUtil.cpp src/fileUtil.h)
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(OPENSSL_USE_STATIC_LIBS TRUE)
set(NLOHMANN_JSON_DIR ${CMAKE_CURRENT_BINARY_DIR}/include/nlohmann_json)

if(NOT EXISTS ${NLOHMANN_JSON_DIR})
  file(MAKE_DIRECTORY ${NLOHMANN_JSON_DIR})
  file(DOWNLOAD https://github.com/nlohmann/json/releases/download/v3.1.2/json.hpp ${NLOHMANN_JSON_DIR}/json.hpp)
endif()
#find_package(nlohmann_json CONFIG REQUIRED)

#INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR})
#set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
#find_package(Gpgme REQUIRED)

INCLUDE_DIRECTORIES(${CURL_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/include #[[${GPGME_INCLUDES]}]])
SET(LIBS ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES})
add_library(curl UNKNOWN IMPORTED)
add_library(openssl UNKNOWN IMPORTED)
set_property(TARGET curl PROPERTY IMPORTED_LOCATION "${CURL_LIBRARIES}")


add_executable(cealr ${SOURCE_FILES})
target_link_libraries(cealr ssl crypto curl)
