cmake_minimum_required(VERSION 3.10)

# set the project name
project(tls_mem C)

if(APPLE)
	set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl/")
endif()

# find_package(Boost REQUIRED chrono system)
find_package(OpenSSL REQUIRED)

# include_directories(${Boost_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

add_compile_options(-Wall -Wextra -pedantic -Werror)

# add the executable
add_executable(tls_mem tls_mem.c)

target_link_libraries (tls_mem -lm ${OPENSSL_LIBRARIES})
