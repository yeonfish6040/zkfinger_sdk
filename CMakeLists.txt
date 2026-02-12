cmake_minimum_required(VERSION 3.20)
project(zkfinger)

set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBUSB QUIET libusb-1.0)
endif()

if(NOT LIBUSB_FOUND)
    set(LIBUSB_ROOT "" CACHE PATH "libusb root")
    set(_libusb_hints "")
    if(APPLE)
        if(EXISTS "/opt/homebrew/opt/libusb")
            list(APPEND _libusb_hints "/opt/homebrew/opt/libusb")
        endif()
        if(EXISTS "/usr/local/opt/libusb")
            list(APPEND _libusb_hints "/usr/local/opt/libusb")
        endif()
    endif()
    if(LIBUSB_ROOT)
        list(APPEND _libusb_hints "${LIBUSB_ROOT}")
    endif()

    find_path(LIBUSB_INCLUDE_DIRS
        NAMES libusb-1.0/libusb.h
        HINTS ${_libusb_hints}
        PATH_SUFFIXES include
    )
    find_library(LIBUSB_LIBRARIES
        NAMES usb-1.0 libusb-1.0
        HINTS ${_libusb_hints}
        PATH_SUFFIXES lib
    )
    if(LIBUSB_INCLUDE_DIRS AND LIBUSB_LIBRARIES)
        set(LIBUSB_FOUND TRUE)
    endif()
endif()

if(NOT LIBUSB_FOUND)
    message(FATAL_ERROR "libusb-1.0 not found. Install libusb + pkg-config or set LIBUSB_ROOT.")
endif()

if(NOT LIBUSB_CFLAGS_OTHER)
    set(LIBUSB_CFLAGS_OTHER "")
endif()

add_library(zkfp SHARED
    src/zkfp.cpp
    src/sensor_libusb.cpp
)
target_include_directories(zkfp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(zkfp PRIVATE
    ${LIBUSB_INCLUDE_DIRS}
)
target_link_libraries(zkfp PRIVATE
    ${LIBUSB_LIBRARIES}
)
target_compile_options(zkfp PRIVATE
    ${LIBUSB_CFLAGS_OTHER}
)

add_library(zkfinger10 SHARED
    src/zkfinger10.cpp
)
target_include_directories(zkfinger10 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(zkfp PRIVATE
    zkfinger10
)


add_executable(zkfp_capture_test
    test/capture_image.cpp
)
target_include_directories(zkfp_capture_test PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(zkfp_capture_test PRIVATE
    zkfp
    zkfinger10
)
