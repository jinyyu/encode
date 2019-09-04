cmake_minimum_required(VERSION 3.5)
project(license)

set(CMAKE_CXX_STANDARD 11)
add_definitions(-Wall)

find_package(PkgConfig REQUIRED)
pkg_check_modules(3rd
                  glib-2.0 REQUIRED
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

add_executable(test main.cpp)
target_link_libraries(test ${LIBS} license)
