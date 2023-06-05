
cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginMoreHashes)

include(ZeekPlugin)

if(COMMAND zeek_add_plugin)
  zeek_add_plugin(
      Zeek
      MoreHashes
      SOURCES
      src/Plugin.cc
      src/MMH3.cc
      src/3rdparty/PMurHash.c
      BIFS
      src/morehashes.bif
      DIST_FILES
      README CHANGES COPYING VERSION)
else()
    zeek_plugin_begin(Zeek MoreHashes)
    zeek_plugin_cc(src/Plugin.cc src/MMH3.cc src/3rdparty/PMurHash.c)
    zeek_plugin_bif(src/morehashes.bif)
    zeek_plugin_dist_files(README COPYING VERSION)
    zeek_plugin_end()
endif()

# zeek_plugin_scripts(
#        scripts/__load__.zeek
#        scripts/__preload__.zeek
#        scripts/types.zeek
#        scripts/Zeek/MoreFileHashes/__load__.zeek
# )

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)
string(REGEX REPLACE "[.-]" " " version_numbers ${VERSION})
separate_arguments(version_numbers)
list(GET version_numbers 0 VERSION_MAJOR)
list(GET version_numbers 1 VERSION_MINOR)
list(GET version_numbers 2 VERSION_PATCH)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
