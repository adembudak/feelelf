cmake_minimum_required(VERSION 3.25.2)

project(feelelf HOMEPAGE_URL https://github.com/adembudak/feelelf LANGUAGES CXX)

option(BUILD_DEMO "A clone of readelf" YES)

add_library(feelelf src/feelelf.cpp)
add_library(feelelf::feelelf ALIAS feelelf)
target_include_directories(feelelf PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

target_sources(feelelf PUBLIC FILE_SET set TYPE HEADERS BASE_DIRS ${PROJECT_SOURCE_DIR}/include FILES include/feelelf/feelelf.h)
install(TARGETS feelelf EXPORT feelelf FILE_SET set DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(EXPORT feelelf DESTINATION lib/cmake/feelelf NAMESPACE feelelf:: FILE feelelfConfig.cmake)

if(BUILD_DEMO)
  find_package(fmt QUIET REQUIRED)
  find_package(CLI11 QUIET REQUIRED)

  add_executable(readelf demo/main.cpp)
  target_link_libraries(readelf PRIVATE feelelf::feelelf fmt::fmt CLI11::CLI11)
endif()
