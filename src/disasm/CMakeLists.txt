set(DISASM_SOURCES
    DisasmModule.cpp
    DisasmModule.h
    DisasmWidget.cpp
    DisasmWidget.h
    HexWidget.cpp
    HexWidget.h
    Disassembler.cpp
    Disassembler.h
    FunctionList.cpp
    FunctionList.h
    EntropyMapWidget.cpp
    EntropyMapWidget.h
    CFGWidget.cpp
    CFGWidget.h
    XrefWidget.cpp
    XrefWidget.h
    ImportsExportsWidget.cpp
    ImportsExportsWidget.h
    SegmentWidget.cpp
    SegmentWidget.h
    PatchEngine.cpp
    PatchEngine.h
    PatchWidget.cpp
    PatchWidget.h
    DataInspector.cpp
    DataInspector.h
    HashWidget.cpp
    HashWidget.h
    BookmarkWidget.cpp
    BookmarkWidget.h
    MemoryMapWidget.cpp
    MemoryMapWidget.h
    TemplateEngine.cpp
    TemplateEngine.h
    TemplateWidget.cpp
    TemplateWidget.h
    HistogramWidget.cpp
    HistogramWidget.h
    DataProcessorEngine.cpp
    DataProcessorEngine.h
    DataProcessorWidget.cpp
    DataProcessorWidget.h
)

add_library(fidra_disasm STATIC ${DISASM_SOURCES})

target_include_directories(fidra_disasm PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_disasm PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    capstone
)
