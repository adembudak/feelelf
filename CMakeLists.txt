cmake_minimum_required(VERSION 3.24.1)

project(
  feelelf
  HOMEPAGE_URL https://github.com/adembudak/feelelf
  LANGUAGES CXX)

find_package(fmt QUIET REQUIRED)
find_package(CLI11 QUIET REQUIRED)

add_library(feelelf src/feelelf.cpp)
target_include_directories(feelelf PUBLIC include)
add_library(feelelf::feelelf ALIAS feelelf)

add_executable(readelf demo/main.cpp)
target_link_libraries(readelf PRIVATE feelelf::feelelf fmt::fmt CLI11::CLI11)
