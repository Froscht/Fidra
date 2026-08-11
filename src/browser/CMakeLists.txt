set(BROWSER_SOURCES
    BrowserModule.cpp
    BrowserModule.h
    BrowserWidget.cpp
    BrowserWidget.h
    BrowserProfile.cpp
    BrowserProfile.h
    JsInjector.cpp
    JsInjector.h
    RequestInterceptor.cpp
    RequestInterceptor.h
)

add_library(fidra_browser STATIC ${BROWSER_SOURCES})

target_include_directories(fidra_browser PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_browser PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::WebEngineWidgets
)
