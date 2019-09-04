cmake_minimum_required(VERSION 3.5)
project(license)

set(CMAKE_CXX_STANDARD 11)
add_definitions(-Wall)

find_package(PkgConfig REQUIRED)
pkg_check_modules(3rd
                  openssl REQUIRED)
include_directories(${3rd_INCLUDE_DIRS})
set(LIBS
    ${3rd_LIBRARIES})

set(SRC
    license.c
    )
add_library(license ${SRC})
target_link_libraries(license  ${LIBS})

set(LIBS
    ${3rd_LIBRARIES}
    license
    )

pkg_check_modules(GoogleTest gtest_main)
if (GoogleTest_FOUND)
    include_directories(${GoogleTest_INCLUDE_DIRS})
    set(LIBS
        ${LIBS}
        ${GoogleTest_LIBRARIES})
endif (GoogleTest_FOUND)

add_executable(test test.cpp)
target_link_libraries(test ${LIBS} license)
