find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
link_libraries(${OPENSSL_LIBRARIES})

add_executable(enroll enroll.c log.c)
