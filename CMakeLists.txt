cmake_minimum_required(VERSION 3.16)

set(VERSION 0.13.0)

project(PQ_GAKE_FSXY VERSION ${VERSION} LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_library(oqs STATIC IMPORTED) # or STATIC instead of SHARED
set_target_properties(oqs PROPERTIES
  IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/liboqs/build/lib/liboqs.a"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/liboqs/build/include"
)

if(NOT DEFINED OPENSSL_ROOT_DIR)
  if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Darwin")
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@1.1")
  elseif(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux")
    set(OPENSSL_ROOT_DIR "/usr")
  endif()
endif()

find_package(OpenSSL 1.1.1 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

enable_testing()

add_subdirectory(src)
add_subdirectory(test)
