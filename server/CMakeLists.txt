cmake_minimum_required(VERSION 3.8)
project(server)

set(CMAKE_CXX_STANDARD 14)

set(SOURCE_FILES
        Server.cpp
        support.c
        support.h
        team.c
        util.h)

# Search OpenSSL
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()


add_executable(server ${SOURCE_FILES})


target_link_libraries(server ${OPENSSL_LIBRARIES} pthread)