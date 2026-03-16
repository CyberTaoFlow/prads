cmake_minimum_required(VERSION 3.14)
project(prads
    VERSION 0.4.0
    DESCRIPTION "Passive Real-time Asset Detection System (Vectorscan edition)"
    LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# -------------------------------------------------------------------
# Build options
# -------------------------------------------------------------------
option(PRADS_USE_JEMALLOC  "Link against jemalloc"        OFF)
option(PRADS_USE_TCMALLOC  "Link against tcmalloc"        OFF)
option(PRADS_BUILD_STATIC  "Build a fully-static binary"  OFF)
option(PRADS_DEBUG          "Enable debug build"           OFF)

# -------------------------------------------------------------------
# Config directory (signatures, fingerprints)
# -------------------------------------------------------------------
set(PRADS_CONFDIR "${CMAKE_INSTALL_PREFIX}/etc/prads"
    CACHE STRING "Runtime configuration directory")
add_compile_definitions(CONFDIR="${PRADS_CONFDIR}/")
add_compile_definitions(__USE_GNU)

if(PRADS_DEBUG)
    add_compile_definitions(DEBUG)
    set(CMAKE_BUILD_TYPE Debug)
else()
    set(CMAKE_BUILD_TYPE Release)
    add_compile_options(-O3)
endif()

# -------------------------------------------------------------------
# Dependencies
# -------------------------------------------------------------------
find_package(PkgConfig REQUIRED)

# libpcap
find_library(PCAP_LIBRARY NAMES pcap)
find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found.  Install libpcap-dev.")
endif()

# Vectorscan / Hyperscan
# Try vectorscan first, fall back to hyperscan
pkg_check_modules(HS QUIET vectorscan)
if(NOT HS_FOUND)
    pkg_check_modules(HS QUIET libhs)
endif()
if(NOT HS_FOUND)
    find_library(HS_LIBRARIES NAMES hs)
    find_path(HS_INCLUDE_DIRS NAMES hs/hs.h)
    if(HS_LIBRARIES AND HS_INCLUDE_DIRS)
        set(HS_FOUND TRUE)
    endif()
endif()
if(NOT HS_FOUND)
    message(FATAL_ERROR
        "Vectorscan (or Hyperscan) not found.\n"
        "Install libvectorscan-dev or libhyperscan-dev.")
endif()

# PCRE2
pkg_check_modules(PCRE2 QUIET libpcre2-8)
if(NOT PCRE2_FOUND)
    find_library(PCRE2_LIBRARIES NAMES pcre2-8)
    find_path(PCRE2_INCLUDE_DIRS NAMES pcre2.h)
    if(PCRE2_LIBRARIES AND PCRE2_INCLUDE_DIRS)
        set(PCRE2_FOUND TRUE)
    endif()
endif()
if(NOT PCRE2_FOUND)
    message(FATAL_ERROR "libpcre2-8 not found.  Install libpcre2-dev.")
endif()

# resolv
find_library(RESOLV_LIBRARY NAMES resolv)

# -------------------------------------------------------------------
# Sources
# -------------------------------------------------------------------
set(PRADS_SOURCES
    src/prads.c
    src/config.c
    src/sys_func.c
    src/assets.c
    src/cxt.c
    src/bstrlib.c
    src/sig_tcp.c
    src/mac.c
    src/dhcp.c
    src/dump_dns.c
    src/hs_engine.c
    src/servicefp/servicefp.c
    src/servicefp/tcps.c
    src/servicefp/tcpc.c
    src/servicefp/udps.c
    src/ipfp/ipfp.c
    src/ipfp/udp_fp.c
    src/ipfp/icmp_fp.c
    src/output-plugins/log_dispatch.c
    src/output-plugins/log_stdout.c
    src/output-plugins/log_file.c
    src/output-plugins/log_fifo.c
    src/output-plugins/log_ringbuffer.c
    src/output-plugins/log_sguil.c
)

# -------------------------------------------------------------------
# Target
# -------------------------------------------------------------------
add_executable(prads ${PRADS_SOURCES})

target_include_directories(prads PRIVATE
    ${PCAP_INCLUDE_DIR}
    ${HS_INCLUDE_DIRS}
    ${PCRE2_INCLUDE_DIRS}
    src/
)

target_link_libraries(prads PRIVATE
    ${PCAP_LIBRARY}
    ${HS_LIBRARIES}
    ${PCRE2_LIBRARIES}
    ${RESOLV_LIBRARY}
    stdc++
    m
)

if(PRADS_USE_JEMALLOC)
    find_library(JEMALLOC_LIB jemalloc)
    target_compile_definitions(prads PRIVATE USE_JEMALLOC)
    target_link_libraries(prads PRIVATE ${JEMALLOC_LIB})
endif()

if(PRADS_USE_TCMALLOC)
    find_library(TCMALLOC_LIB tcmalloc)
    target_link_libraries(prads PRIVATE ${TCMALLOC_LIB})
endif()

if(PRADS_BUILD_STATIC)
    set_target_properties(prads PROPERTIES LINK_FLAGS "-static")
endif()

# -------------------------------------------------------------------
# Git version in RELEASE define
# -------------------------------------------------------------------
execute_process(
    COMMAND git describe --always --dirty
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
if(GIT_VERSION)
    target_compile_definitions(prads PRIVATE RELEASE="${GIT_VERSION}")
else()
    target_compile_definitions(prads PRIVATE RELEASE="")
endif()

# -------------------------------------------------------------------
# Install
# -------------------------------------------------------------------
include(GNUInstallDirs)

install(TARGETS prads RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(FILES etc/prads.conf DESTINATION ${PRADS_CONFDIR})

install(FILES
    etc/tcp-syn.fp etc/tcp-synack.fp etc/tcp-fin.fp
    etc/tcp-rst.fp etc/tcp-stray-ack.fp
    etc/tcp-service.sig etc/tcp-clients.sig etc/udp-service.sig
    etc/service-string.sig etc/icmp-data.sig etc/mtu.sig
    etc/os.sig etc/mac.sig etc/eth.sig
    DESTINATION ${PRADS_CONFDIR})

install(PROGRAMS tools/prads-asset-report tools/prads2snort
    DESTINATION ${CMAKE_INSTALL_BINDIR})
