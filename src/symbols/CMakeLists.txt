set(SYMBOLS_SOURCES
    SymbolResolver.cpp
    SymbolResolver.h
    SymbolServer.h
    SymbolWidget.cpp
    SymbolWidget.h
    SymbolModule.cpp
    SymbolModule.h
)

add_library(fidra_symbols STATIC ${SYMBOLS_SOURCES})

target_include_directories(fidra_symbols PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_symbols PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)
