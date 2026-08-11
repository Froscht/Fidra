set(BINDIFF_SOURCES
    BinDiffEngine.cpp
    BinDiffEngine.h
    BinDiffWidget.cpp
    BinDiffWidget.h
    BinDiffModule.cpp
    BinDiffModule.h
)

add_library(fidra_bindiff STATIC ${BINDIFF_SOURCES})

target_include_directories(fidra_bindiff PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_bindiff PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)
