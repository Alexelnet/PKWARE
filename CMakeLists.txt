cmake_minimum_required(VERSION 3.31)
project(PKWARE)

set(CMAKE_CXX_STANDARD 23)


# Thirdparty Libraries
add_subdirectory(Thirdparty/Fmt)
add_subdirectory(Thirdparty/libzip)




add_executable(PKWARE Main.cpp)

target_link_libraries(PKWARE fmt::fmt libzip::zip)
