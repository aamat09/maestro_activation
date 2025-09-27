cmake_minimum_required(VERSION 3.16)
project(maestro_device_activation_client)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

# Try to find jsoncpp
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)

if(NOT JSONCPP_FOUND)
    # Fallback for systems where jsoncpp is not found via pkg-config
    find_path(JSONCPP_INCLUDE_DIR json/json.h
        PATHS /usr/include/jsoncpp /usr/local/include/jsoncpp)
    find_library(JSONCPP_LIBRARY NAMES jsoncpp
        PATHS /usr/lib /usr/local/lib)

    if(JSONCPP_INCLUDE_DIR AND JSONCPP_LIBRARY)
        set(JSONCPP_LIBRARIES ${JSONCPP_LIBRARY})
        set(JSONCPP_INCLUDE_DIRS ${JSONCPP_INCLUDE_DIR})
    else()
        message(FATAL_ERROR "jsoncpp library not found")
    endif()
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${JSONCPP_INCLUDE_DIRS})

# Source files
set(CLIENT_SOURCES
    maestro_activation_client.cpp
)

# Create test executable
add_executable(test_activation
    test_activation.cpp
    ${CLIENT_SOURCES}
)

# Create static library for integration
add_library(maestro_activation_client STATIC
    ${CLIENT_SOURCES}
)

# Link libraries for test program
target_link_libraries(test_activation
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${CURL_LIBRARIES}
    ${JSONCPP_LIBRARIES}
)

# Link libraries for static library
target_link_libraries(maestro_activation_client
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${CURL_LIBRARIES}
    ${JSONCPP_LIBRARIES}
)

# Include directories for targets
target_include_directories(test_activation PRIVATE ${CURL_INCLUDE_DIRS})
target_include_directories(maestro_activation_client PRIVATE ${CURL_INCLUDE_DIRS})

# Compiler flags for security
target_compile_options(test_activation PRIVATE
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIE
)

target_compile_options(maestro_activation_client PRIVATE
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIC
)

target_link_options(test_activation PRIVATE
    -pie
    -Wl,-z,relro
    -Wl,-z,now
)

# Install targets
install(TARGETS maestro_activation_client
    ARCHIVE DESTINATION /opt/maestro/activation/lib
)

install(FILES maestro_activation_client.h
    DESTINATION /opt/maestro/activation/include
)

install(TARGETS test_activation
    RUNTIME DESTINATION /opt/maestro/activation/bin
)