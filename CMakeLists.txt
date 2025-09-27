cmake_minimum_required(VERSION 3.16)
project(maestro_activation_server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Drogon REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/server/include)

# Source files
file(GLOB_RECURSE SERVER_SOURCES "server/src/*.cpp")

# Create server executable
add_executable(maestro_activation_server ${SERVER_SOURCES})

# Link libraries
target_link_libraries(maestro_activation_server
    PRIVATE
    Drogon::Drogon
    SQLite::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Compiler flags for security
target_compile_options(maestro_activation_server PRIVATE
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIE
)

target_link_options(maestro_activation_server PRIVATE
    -pie
    -Wl,-z,relro
    -Wl,-z,now
)

# Install target
install(TARGETS maestro_activation_server
    RUNTIME DESTINATION /opt/maestro/activation/bin
)

# Install configuration files
install(DIRECTORY config/ DESTINATION /opt/maestro/activation/config)

# Install database schema
install(DIRECTORY database/ DESTINATION /opt/maestro/activation/database)