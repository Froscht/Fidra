set(NETWORK_SOURCES
    NetworkModule.cpp
    NetworkModule.h
    NetworkWidget.cpp
    NetworkWidget.h
    PacketCapture.cpp
    PacketCapture.h
    PacketModel.cpp
    PacketModel.h
    ProtocolDissector.cpp
    ProtocolDissector.h
)

add_library(fidra_network STATIC ${NETWORK_SOURCES})

target_include_directories(fidra_network PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_network PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)
