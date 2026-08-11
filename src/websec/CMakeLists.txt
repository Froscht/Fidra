set(WEBSEC_SOURCES
    WebSecModule.cpp
    WebSecModule.h
    WebSecWidget.cpp
    WebSecWidget.h
    HttpProxy.cpp
    HttpProxy.h
    RepeaterWidget.cpp
    RepeaterWidget.h
    IntruderWidget.cpp
    IntruderWidget.h
    DecoderWidget.cpp
    DecoderWidget.h
)

add_library(fidra_websec STATIC ${WEBSEC_SOURCES})

target_include_directories(fidra_websec PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_websec PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)
