cmake_minimum_required(VERSION 3.0)

project(
    "Diffie-Hellman key generator"
    VERSION 0.3.2
    LANGUAGES C
)

set(OPENSSL_1_0_SOURCE_PATH)
set(OPENSSL_1_1_SOURCE_PATH)
set(OPENSSL_3_0_SOURCE_PATH)

set(C_STANDARD C99)

if(MSVC)
    string(REGEX REPLACE "/W[1-3]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
else()
    add_compile_options(-Wall -Wextra)
endif()

find_package(PkgConfig REQUIRED)

pkg_check_modules(OPENSSL_1_0 libcrypto>=1.0.0 libcrypto<1.1.1)
pkg_check_modules(OPENSSL_1_1 libcrypto>=1.1.0 libcrypto<3.0)
pkg_check_modules(OPENSSL_3_0 libcrypto>=3.0)

if(OPENSSL_1_0_SOURCE_PATH)
    find_library(OPENSSL_1_0_LIBRARY crypto ${OPENSSL_1_0_SOURCE_PATH} NO_DEFAULT_PATH)

    if(NOT ${OPENSSL_1_0_LIBRARY} STREQUAL "OPENSSL_1_0_LIBRARY-NOTFOUND")
        cmake_path(APPEND OPENSSL_1_0_SOURCE_PATH "include" OUTPUT_VARIABLE OPENSSL_1_0_INCLUDE_PATH)
        add_executable(dh_key_gen_openssl_1_0 dh_key_gen_openssl.c dh_key_gen.c dh_params.c)
        target_include_directories(dh_key_gen_openssl_1_0 BEFORE PRIVATE ${OPENSSL_1_0_SOURCE_PATH} ${OPENSSL_1_0_INCLUDE_PATH})
        target_link_directories(dh_key_gen_openssl_1_0 BEFORE PRIVATE ${OPENSSL_1_0_SOURCE_PATH})
        target_link_libraries(dh_key_gen_openssl_1_0 PRIVATE crypto)
    endif()
elseif(OPENSSL_1_0_FOUND)
    add_executable(dh_key_gen_openssl_1_0 dh_key_gen_openssl.c dh_key_gen.c dh_params.c)
    target_link_libraries(dh_key_gen_openssl_1_0 ${OPENSSL_1_0_LDFLAGS})
endif()

if(OPENSSL_1_1_SOURCE_PATH)
    find_library(OPENSSL_1_1_LIBRARY crypto ${OPENSSL_1_1_SOURCE_PATH} NO_DEFAULT_PATH)

    if(NOT ${OPENSSL_1_1_LIBRARY} STREQUAL "OPENSSL_1_1_LIBRARY-NOTFOUND")
        cmake_path(APPEND OPENSSL_1_1_SOURCE_PATH "include" OUTPUT_VARIABLE OPENSSL_1_1_INCLUDE_PATH)
        add_executable(dh_key_gen_openssl_1_1 dh_key_gen_openssl.c dh_key_gen.c dh_params.c)
        target_include_directories(dh_key_gen_openssl_1_1 BEFORE PRIVATE ${OPENSSL_1_1_INCLUDE_PATH})
        target_link_directories(dh_key_gen_openssl_1_1 BEFORE PRIVATE ${OPENSSL_1_1_SOURCE_PATH})
        target_link_libraries(dh_key_gen_openssl_1_1 PRIVATE crypto)
    endif()
elseif(OPENSSL_1_1_FOUND)
    add_executable(dh_key_gen_openssl_1_1 dh_key_gen_openssl.c dh_key_gen.c dh_params.c)
    target_link_libraries(dh_key_gen_openssl_1_1 ${OPENSSL_1_1_LDFLAGS})
endif()

if(OPENSSL_3_0_SOURCE_PATH)
    find_library(OPENSSL_3_0_LIBRARY crypto ${OPENSSL_3_0_SOURCE_PATH} NO_DEFAULT_PATH)

    if(NOT ${OPENSSL_3_0_LIBRARY} STREQUAL "OPENSSL_3_0_LIBRARY-NOTFOUND")
        cmake_path(APPEND OPENSSL_3_0_SOURCE_PATH "include" OUTPUT_VARIABLE OPENSSL_3_0_INCLUDE_PATH)
        add_executable(dh_key_gen_openssl_3_0 dh_key_gen_openssl.c dh_key_gen.c dh_params.c)
        target_include_directories(dh_key_gen_openssl_3_0 BEFORE PRIVATE ${OPENSSL_3_0_INCLUDE_PATH})
        target_link_directories(dh_key_gen_openssl_3_0 BEFORE PRIVATE ${OPENSSL_3_0_SOURCE_PATH})
        target_compile_definitions(dh_key_gen_openssl_3_0 PRIVATE -DOPENSSL_API_COMPAT=0x10101000L)
        target_link_libraries(dh_key_gen_openssl_3_0 PRIVATE crypto)
    endif()
elseif(OPENSSL_3_0_FOUND)
    add_executable(dh_key_gen_openssl_3_0 dh_key_gen_openssl.c dh_key_gen.c dh_params.c)
    target_compile_definitions(dh_key_gen_openssl_3_0 PRIVATE -DOPENSSL_API_COMPAT=0x10101000L)
    target_link_libraries(dh_key_gen_openssl_3_0 ${OPENSSL_3_0_LDFLAGS})
endif()
