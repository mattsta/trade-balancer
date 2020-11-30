cmake_minimum_required(VERSION 3.10)

project(lbsocket C)

option(ENABLE_PROGRAMS "Build mbed TLS programs." OFF)
option(ENABLE_TESTING "Build mbed TLS tests." OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_subdirectory(mbedtls)
add_library(ktlswrapper SHARED ktlswrapper.c)
add_executable(connect-demo connect-demo.c)
add_executable(lb lb.c)

include_directories(mbedtls/include)
target_compile_definitions(ktlswrapper PRIVATE _GNU_SOURCE)

if (CMAKE_BUILD_TYPE STREQUAL RELEASE)
    target_compile_options(ktlswrapper PRIVATE -ffunction-sections -fdata-sections)
endif()

set_target_properties(ktlswrapper PROPERTIES LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/ktlswrapper.version")
set_target_properties(ktlswrapper PROPERTIES LINK_FLAGS_RELEASE "-Wl,--gc-sections -s")

target_link_libraries(ktlswrapper mbedtls dl)
target_link_libraries(connect-demo ktlswrapper)
target_link_libraries(lb ktlswrapper m rt)
