cmake_minimum_required(VERSION 3.0)

project(
    "Diffie-Hellman key generator"
    VERSION 0.3.2
    LANGUAGES C
)

set(OPENSSL_1_0_SOURCE_PATH)
set(OPENSSL_1_1_SOURCE_PATH)
set(BORINGSSL_SOURCE_PATH)
set(LIBRESSL_LIBRARY_PATH)

find_package(PkgConfig REQUIRED)

pkg_check_modules(OPENSSL_1_0 libcrypto>=1.0.0 libcrypto<1.1.1)
pkg_check_modules(OPENSSL_1_1 libcrypto>=1.1.0 libcrypto<3.0)
pkg_check_modules(OPENSSL_3_0 libcrypto>=3.0)
pkg_check_modules(WOLFSSL wolfssl>=5.0)
find_library(MBEDTLS mbedcrypto)

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

if(NOT ${BORINGSSL_SOURCE_PATH} STREQUAL "")
    cmake_path(APPEND BORINGSSL_SOURCE_PATH "crypto" OUTPUT_VARIABLE BORINGSSL_LIBRARY_PATH)
    find_library(BORINGSSL_LIBRARY crypto ${BORINGSSL_LIBRARY_PATH} NO_DEFAULT_PATH)

    if(NOT ${BORINGSSL_LIBRARY} STREQUAL "BORINGSSL_LIBRARY-NOTFOUND")
        cmake_path(APPEND BORINGSSL_SOURCE_PATH "include" OUTPUT_VARIABLE BORINGSSL_INCLUDE_PATH)

        add_executable(dh_key_gen_boringssl dh_key_gen_openssl.c dh_key_gen.c dh_params.c)
        target_include_directories(dh_key_gen_boringssl BEFORE PRIVATE ${BORINGSSL_INCLUDE_PATH})
        target_link_directories(dh_key_gen_boringssl BEFORE PRIVATE ${BORINGSSL_LIBRARY_PATH})
        target_link_libraries(dh_key_gen_boringssl ${BORINGSSL_LIBRARY})
        target_compile_definitions(dh_key_gen_boringssl PRIVATE)
    endif()
endif()

if(NOT ${LIBRESSL_SOURCE_PATH} STREQUAL "")
    cmake_path(APPEND LIBRESSL_SOURCE_PATH "crypto/.libs" OUTPUT_VARIABLE LIBRESSL_LIBRARY_PATH)
    find_library(LIBRESSL_LIBRARY crypto ${LIBRESSL_LIBRARY_PATH} NO_DEFAULT_PATH)

    if(NOT ${LIBRESSL_LIBRARY} STREQUAL "LIBRESSL_LIBRARY-NOTFOUND")
        cmake_path(APPEND LIBRESSL_SOURCE_PATH "include" OUTPUT_VARIABLE LIBRESSL_INCLUDE_PATH)

        add_executable(dh_key_gen_libressl dh_key_gen_openssl.c dh_key_gen.c dh_params.c)
        target_include_directories(dh_key_gen_libressl BEFORE PRIVATE ${LIBRESSL_INCLUDE_PATH})
        target_link_directories(dh_key_gen_libressl BEFORE PRIVATE ${LIBRESSL_LIBRARY_PATH})
        target_link_libraries(dh_key_gen_libressl ${LIBRESSL_LIBRARY})
        target_compile_definitions(dh_key_gen_libressl PRIVATE)
    endif()
endif()

if(WOLFSSL_FOUND)
    add_executable(dh_key_gen_wolfssl dh_key_gen_wolfssl.c dh_key_gen.c dh_params.c)
    target_link_libraries(dh_key_gen_wolfssl ${WOLFSSL_LIBRARIES})
    target_compile_definitions(dh_key_gen_wolfssl PRIVATE)
endif()

if(MBEDTLS)
    add_executable(dh_key_gen_mbedtls dh_key_gen_mbedtls.c dh_key_gen.c dh_params.c)
    target_link_libraries(dh_key_gen_mbedtls mbedcrypto)
    target_compile_definitions(dh_key_gen_mbedtls PRIVATE)
endif()
