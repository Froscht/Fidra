set(ANALYSIS_SOURCES
    AnalysisTypes.h
    AnalysisDatabase.h
    AnalysisDatabase.cpp
    AnalysisEngine.h
    AnalysisEngine.cpp
    SignatureMatcher.h
    SignatureMatcher.cpp
    IdaShim.cpp
)

add_library(fidra_analysis STATIC ${ANALYSIS_SOURCES})

target_include_directories(fidra_analysis PUBLIC
    ${FIDRA_INCLUDE_DIR}
)

target_include_directories(fidra_analysis PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_analysis PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Concurrent
    capstone
)
