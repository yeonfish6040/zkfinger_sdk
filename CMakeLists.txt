cmake_minimum_required(VERSION 4.1)
project(untitled16)

set(CMAKE_CXX_STANDARD 20)

add_library(zkfp SHARED
    src/zkfp.cpp
)
target_include_directories(zkfp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(untitled16 main.cpp)
target_include_directories(untitled16 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
