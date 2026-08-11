set(UNPACKER_SOURCES
    UnpackerModule.cpp
    UnpackerModule.h
    UnpackerWidget.cpp
    UnpackerWidget.h
    PeParser.cpp
    PeParser.h
    EntropyWidget.cpp
    EntropyWidget.h
    IatRebuilder.cpp
    IatRebuilder.h
)

add_library(fidra_unpacker STATIC ${UNPACKER_SOURCES})

target_include_directories(fidra_unpacker PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_unpacker PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    LIEF::LIEF
)
