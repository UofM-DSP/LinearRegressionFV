cmake_minimum_required(VERSION 3.8)
project(linearRegressionFV)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp cloud.cpp fvnamespace.h decrypt.cpp decrypt.h)
add_executable(linearRegressionFV ${SOURCE_FILES})