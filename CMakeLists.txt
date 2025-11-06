cmake_minimum_required(VERSION 3.10)
project(PacketAnalyzer)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt6
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

# Enable automoc for Qt
set(CMAKE_AUTOMOC ON)

# Source files
set(SOURCES
        main.cpp
        MainWindow.cpp
        PacketTableModel.cpp
        PacketCapture.cpp
)

# Header files
set(HEADERS
        MainWindow.h
        PacketTableModel.h
        PacketCapture.h
        PacketInfo.h
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Link Qt libraries
target_link_libraries(${PROJECT_NAME}
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(${PROJECT_NAME} ws2_32)
    add_definitions(-D_WIN32_WINNT=0x0601)

    # Find windeployqt
    get_target_property(QT_QMAKE_EXECUTABLE Qt6::qmake IMPORTED_LOCATION)
    get_filename_component(QT_BIN_DIR "${QT_QMAKE_EXECUTABLE}" DIRECTORY)
    find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${QT_BIN_DIR}")

    # Run windeployqt after build to copy Qt DLLs
    if(WINDEPLOYQT_EXECUTABLE)
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND "${WINDEPLOYQT_EXECUTABLE}" --no-translations --no-system-d3d-compiler --no-opengl-sw "$<TARGET_FILE:${PROJECT_NAME}>"
                COMMENT "Running windeployqt to copy Qt DLLs..."
        )
    endif()
endif()

# Installation
install(TARGETS ${PROJECT_NAME} DESTINATION bin)