cmake_minimum_required(VERSION 3.24.1)

project(
  feelelf
  HOMEPAGE_URL https://github.com/adembudak/feelelf
  LANGUAGES CXX)

find_package(fmt QUIET REQUIRED)
find_package(CLI11 QUIET REQUIRED)

add_library(elf elf.cpp)
add_library(elf::elf ALIAS elf)

add_executable(feelelf main.cpp)
target_link_libraries(feelelf PRIVATE elf::elf fmt::fmt CLI11::CLI11)
