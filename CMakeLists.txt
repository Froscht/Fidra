cmake_minimum_required(VERSION 3.24)
project(Fidra VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

if(MSVC)
    add_compile_options(/W4 /MP /Zc:__cplusplus)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network Concurrent)
find_package(Qt6 COMPONENTS WebEngineWidgets QUIET)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED IMPORTED_TARGET capstone)
add_library(capstone ALIAS PkgConfig::CAPSTONE)

find_package(nlohmann_json 3 QUIET)
if(NOT nlohmann_json_FOUND)
    add_library(nlohmann_json_header INTERFACE)
    target_include_directories(nlohmann_json_header INTERFACE /usr/include)
    add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json_header)
endif()

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

FetchContent_Declare(LIEF
    GIT_REPOSITORY https://github.com/lief-project/LIEF.git
    GIT_TAG 0.15.1
    GIT_SHALLOW TRUE
)
set(LIEF_PYTHON_API OFF CACHE BOOL "" FORCE)
set(LIEF_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LIEF_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(LIEF)

set(FIDRA_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)

add_subdirectory(src/core)
add_subdirectory(src/disasm)
add_subdirectory(src/debugger)
add_subdirectory(src/scanner)
add_subdirectory(src/unpacker)
add_subdirectory(src/network)
add_subdirectory(src/websec)
add_subdirectory(src/mcp)
add_subdirectory(src/dumper)
add_subdirectory(src/structeditor)
add_subdirectory(src/diff)
add_subdirectory(src/decompiler)
add_subdirectory(src/plugins)
add_subdirectory(src/bindiff)
add_subdirectory(src/project)
add_subdirectory(src/analysis)
add_subdirectory(src/symbols)
add_subdirectory(src/callgraph)
add_subdirectory(src/scripting)
if(Qt6WebEngineWidgets_FOUND)
    add_subdirectory(src/browser)
endif()

option(FIDRA_BUILD_TESTS "Build the analysis test driver" OFF)
if(FIDRA_BUILD_TESTS)
    add_executable(fidra_test_analysis test_analysis.cpp)
    target_include_directories(fidra_test_analysis PRIVATE
        ${FIDRA_INCLUDE_DIR}
        ${CMAKE_SOURCE_DIR}
    )
    target_link_libraries(fidra_test_analysis PRIVATE
        fidra_analysis
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Concurrent
        capstone
    )
    enable_testing()
    add_test(NAME analysis_smoke COMMAND fidra_test_analysis ${CMAKE_COMMAND})
endif()
