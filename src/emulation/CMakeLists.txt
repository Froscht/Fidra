set(EMULATION_SOURCES
    EmulationEngine.h
    EmulationEngine.cpp
    EmulationModule.h
    EmulationModule.cpp
)

add_library(fidra_emulation STATIC ${EMULATION_SOURCES})
set_target_properties(fidra_emulation PROPERTIES AUTOMOC ON)

target_include_directories(fidra_emulation PUBLIC
    ${FIDRA_INCLUDE_DIR}
)

target_include_directories(fidra_emulation PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_emulation PUBLIC
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    fidra_analysis
)

if(FIDRA_ENABLE_UNICORN AND TARGET unicorn)
    target_compile_definitions(fidra_emulation PRIVATE FIDRA_HAS_UNICORN=1)
    target_link_libraries(fidra_emulation PUBLIC unicorn)
endif()
