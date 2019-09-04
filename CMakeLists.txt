cmake_minimum_required(VERSION 3.5)
project(encode)

set(CMAKE_CXX_STANDARD 11)
add_definitions(-Wall)

find_package(PkgConfig REQUIRED)
pkg_check_modules(3rd
                  openssl REQUIRED)
include_directories(${3rd_INCLUDE_DIRS})
set(LIBS
    ${3rd_LIBRARIES})


add_executable(test main.cpp)
target_link_libraries(test ${LIBS})
