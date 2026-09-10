cmake_minimum_required(VERSION 3.24)
project(Fidra VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

if(MSVC)
    add_compile_options(/W4 /MP /Zc:__cplusplus /utf-8 /permissive-)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network Concurrent)
find_package(Qt6 COMPONENTS WebEngineWidgets QUIET)

# Capstone: prefer proper CMake config (vcpkg on Windows, distros that ship it),
# fall back to pkg-config on POSIX where it is the norm.
find_package(capstone CONFIG QUIET)
if(TARGET capstone::capstone)
    add_library(capstone ALIAS capstone::capstone)
elseif(TARGET capstone)
    # target already provided
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CAPSTONE REQUIRED IMPORTED_TARGET capstone)
    add_library(capstone ALIAS PkgConfig::CAPSTONE)
endif()

# nlohmann_json: use the config package if present (vcpkg, most distros).
# Otherwise, fetch a header-only copy so the build is self-contained on any OS.
find_package(nlohmann_json 3 CONFIG QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
        GIT_SHALLOW TRUE
    )
    set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(nlohmann_json)
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

option(FIDRA_ENABLE_LIBDECOMP "Build libdecomp submodule as alternate decompiler backend" OFF)
option(FIDRA_ENABLE_TRITON "Build Triton submodule for symbolic execution / vuln chains" OFF)

if(FIDRA_ENABLE_LIBDECOMP)
    if(EXISTS ${CMAKE_SOURCE_DIR}/third_party/libdecomp/CMakeLists.txt)
        # libdecomp's own CMakeLists uses ${CMAKE_SOURCE_DIR} internally which
        # breaks when consumed as add_subdirectory. Build it ourselves.
        file(GLOB_RECURSE _LIBDECOMP_SRC CONFIGURE_DEPENDS
            ${CMAKE_SOURCE_DIR}/third_party/libdecomp/libdecomp/*.c)
        add_library(libdecomp STATIC ${_LIBDECOMP_SRC})
        target_include_directories(libdecomp PUBLIC
            ${CMAKE_SOURCE_DIR}/third_party/libdecomp/include)
        target_compile_definitions(libdecomp PRIVATE
            LIBDECOMP_VERSION_MAJOR=0 LIBDECOMP_VERSION_MINOR=1
            LIBDECOMP_ENABLE_BUILTIN_BACKEND_CAPSTONE=1)
        target_link_libraries(libdecomp PUBLIC capstone)
        target_compile_options(libdecomp PRIVATE -Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable)
    else()
        message(FATAL_ERROR "FIDRA_ENABLE_LIBDECOMP set but third_party/libdecomp is empty. Run: git submodule update --init --recursive")
    endif()
endif()

if(FIDRA_ENABLE_TRITON)
    if(EXISTS ${CMAKE_SOURCE_DIR}/third_party/Triton/CMakeLists.txt)
        set(TRITON_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(TRITON_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
        add_subdirectory(third_party/Triton EXCLUDE_FROM_ALL)
    else()
        message(FATAL_ERROR "FIDRA_ENABLE_TRITON set but third_party/Triton is empty. Run: git submodule update --init --recursive")
    endif()
endif()

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
add_subdirectory(src/graphrag)
if(Qt6WebEngineWidgets_FOUND)
    add_subdirectory(src/browser)
endif()

option(FIDRA_BUILD_MULTIBINARY "Build multibinary index/project module (ported from AiDA)" OFF)
if(FIDRA_BUILD_MULTIBINARY)
    add_subdirectory(src/multibinary)
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
