CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(quicly)

SET(CMAKE_C_FLAGS "-std=c99 -Wall -O0 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")

INCLUDE_DIRECTORIES(
    deps/klib
    deps/picotls/include
    deps/picotest
    include)

SET(MINICRYPTO_LIBRARY_FILES
    deps/picotls/deps/micro-ecc/uECC.c
    deps/picotls/deps/cifra/src/aes.c
    deps/picotls/deps/cifra/src/blockwise.c
    deps/picotls/deps/cifra/src/chacha20.c
    deps/picotls/deps/cifra/src/chash.c
    deps/picotls/deps/cifra/src/curve25519.c
    deps/picotls/deps/cifra/src/drbg.c
    deps/picotls/deps/cifra/src/hmac.c
    deps/picotls/deps/cifra/src/gcm.c
    deps/picotls/deps/cifra/src/gf128.c
    deps/picotls/deps/cifra/src/modes.c
    deps/picotls/deps/cifra/src/poly1305.c
    deps/picotls/deps/cifra/src/sha256.c
    deps/picotls/deps/cifra/src/sha512.c)

SET(PICOTLS_CORE_FILES
    deps/picotls/lib/picotls.c
    deps/picotls/lib/pembase64.c)

FIND_PACKAGE(OpenSSL)
IF (OPENSSL_FOUND)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPICOTLS_USE_OPENSSL=1")

    INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})

    SET(PICOTLS_FILES ${PICOTLS_CORE_FILES}
        deps/picotls/lib/openssl.c)
ELSE ()
    INCLUDE_DIRECTORIES(
        deps/picotls/deps/cifra/src/ext
        deps/picotls/deps/cifra/src
        deps/picotls/deps/micro-ecc)

    SET(PICOTLS_FILES ${PICOTLS_CORE_FILES} ${MINICRYPTO_LIBRARY_FILES}
        deps/picotls/lib/cifra.c
        deps/picotls/lib/minicrypto-pem.c
        deps/picotls/lib/uecc.c
        deps/picotls/lib/asn1.c
        deps/picotls/lib/ffx.c)
ENDIF ()

SET(QUICLY_LIBRARY_FILES
    lib/frame.c
    lib/cc-reno.c
    lib/defaults.c
    lib/quicly.c
    lib/ranges.c
    lib/recvstate.c
    lib/sendstate.c
    lib/sentmap.c
    lib/streambuf.c
    quic.c
    ${PICOTLS_FILES})

SET(UNITTEST_SOURCE_FILES
    deps/picotest/picotest.c
    t/frame.c
    t/maxsender.c
    t/loss.c
    t/ranges.c
    t/sentmap.c
    t/simple.c
    t/stream-concurrency.c
    t/test.c)

ADD_LIBRARY(quicly ${QUICLY_LIBRARY_FILES})

IF (OPENSSL_FOUND)
ADD_EXECUTABLE(cli src/cli.c)
TARGET_LINK_LIBRARIES(cli quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_EXECUTABLE(test.t ${UNITTEST_SOURCE_FILES})
TARGET_LINK_LIBRARIES(test.t quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})
ENDIF ()

ADD_EXECUTABLE(examples-echo examples/echo.c)
TARGET_LINK_LIBRARIES(examples-echo quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})
ADD_EXECUTABLE(echo examples/echo2.c)
TARGET_LINK_LIBRARIES(echo quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_EXECUTABLE(udpfw t/udpfw.c)

ADD_CUSTOM_TARGET(check env BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} prove --exec "sh -c" -v ${CMAKE_CURRENT_BINARY_DIR}/*.t t/*.t
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS cli test.t)

ADD_CUSTOM_TARGET(format clang-format -i `git ls-files include lib src t | egrep '\\.[ch]$$'`)

IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
     SET(CMAKE_C_FLAGS "-D_GNU_SOURCE -pthread ${CMAKE_C_FLAGS}")
ENDIF ()

IF (BUILD_FUZZER)
    IF(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        MESSAGE(FATAL_ERROR "The fuzzer needs clang as a compiler")
    ENDIF()
    ADD_EXECUTABLE(quicly-fuzzer-packet fuzz/packet.cc)
    SET(LIB_FUZZER "${CMAKE_CURRENT_BINARY_DIR}/libFuzzer.a")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=address,undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fno-omit-frame-pointer -fsanitize=address,undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters")
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_C_FLAGS}")

    ADD_CUSTOM_TARGET(libFuzzer ${CMAKE_CURRENT_SOURCE_DIR}/misc/build_libFuzzer.sh WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    ADD_DEPENDENCIES(quicly-fuzzer-packet libFuzzer)
    TARGET_LINK_LIBRARIES(quicly-fuzzer-packet quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS} ${LIB_FUZZER})
ENDIF()

