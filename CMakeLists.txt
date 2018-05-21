cmake_minimum_required(VERSION 3.0.0)

project(enroll)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -Wall -pthread")

subdirs(src)
