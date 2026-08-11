find_package(Qt6 REQUIRED COMPONENTS Concurrent)

set(SCANNER_SOURCES
    ScannerModule.cpp
    ScannerModule.h
    ScannerWidget.cpp
    ScannerWidget.h
    ScanEngine.cpp
    ScanEngine.h
    PointerScanner.cpp
    PointerScanner.h
    AddressList.cpp
    AddressList.h
    YaraEngine.cpp
    YaraEngine.h
    YaraWidget.cpp
    YaraWidget.h
)

add_library(fidra_scanner STATIC ${SCANNER_SOURCES})

target_include_directories(fidra_scanner PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_scanner PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Concurrent
)
