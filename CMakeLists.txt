cmake_minimum_required(VERSION 3.8)
project(httpc_example C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Your original header-only library setup.
add_library(httpc INTERFACE)
target_sources(httpc INTERFACE "${CMAKE_SOURCE_DIR}/src/httpc.h")
target_include_directories(httpc INTERFACE "${CMAKE_SOURCE_DIR}/src")

set_target_properties(httpc PROPERTIES
  INTERFACE_C_STANDARD 17
)

# Example or test executable that uses the header-only library.
# Ensure you have at least one source file for the example or test.
add_executable(httpc_example "src/main.c")
target_link_libraries(httpc_example PRIVATE httpc)

