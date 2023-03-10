cmake_minimum_required(VERSION 3.25.2)

project(feelelf HOMEPAGE_URL https://github.com/adembudak/feelelf LANGUAGES CXX)

include(GNUInstallDirs)

if(DEFINED CMAKE_BUILD_TYPE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug;Release;RelWithDebInfo;MinSizeRel")
endif()

option(BUILD_DEMO "A clone of readelf" YES)

add_library(feelelf src/feelelf.cpp)
add_library(feelelf::feelelf ALIAS feelelf)
target_include_directories(feelelf PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

target_sources(feelelf PUBLIC FILE_SET set TYPE HEADERS BASE_DIRS ${PROJECT_SOURCE_DIR}/include FILES include/feelelf/feelelf.h)
install(TARGETS feelelf EXPORT feelelf FILE_SET set DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT feelelf DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/feelelf NAMESPACE feelelf:: FILE feelelfConfig.cmake)

if(BUILD_DEMO)
  find_package(fmt QUIET REQUIRED)
  find_package(CLI11 QUIET REQUIRED)

  add_executable(readelf examples/main.cpp)
  target_link_libraries(readelf PRIVATE feelelf::feelelf fmt::fmt CLI11::CLI11)
endif()

set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${CMAKE_INSTALL_PREFIX})
set(libdir ${CMAKE_INSTALL_FULL_LIBDIR})
set(includedir ${CMAKE_INSTALL_FULL_INCLUDEDIR})
set(feelelf_target feelelf)

configure_file(${PROJECT_SOURCE_DIR}/cmake/feelelf.pc.in feelelf.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/feelelf.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
