set(DECOMPILER_SOURCES
    DecompTypes.h
    Lifter.h
    Lifter.cpp
    Optimizer.h
    Optimizer.cpp
    CodeGenerator.h
    CodeGenerator.cpp
    DecompilerWidget.h
    DecompilerWidget.cpp
    DecompilerModule.h
    DecompilerModule.cpp
)

add_library(fidra_decompiler STATIC ${DECOMPILER_SOURCES})

target_include_directories(fidra_decompiler PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_decompiler PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    capstone
)

set_target_properties(fidra_decompiler PROPERTIES AUTOMOC ON)
