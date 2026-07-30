cmake_minimum_required(VERSION 3.20)

project(he_voting_count LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenFHE CONFIG REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} ${OpenFHE_EXE_LINKER_FLAGS}")

add_executable(
    he_voting_crypto
    cpp/src/main.cpp
    cpp/src/openfhe_vote_evaluator.cpp
)

target_include_directories(
    he_voting_crypto
    PRIVATE
    cpp/include
    "${OpenFHE_INCLUDE}"
    "${OpenFHE_INCLUDE}/third-party/include"
    "${OpenFHE_INCLUDE}/core"
    "${OpenFHE_INCLUDE}/pke"
    "${OpenFHE_INCLUDE}/binfhe"
)

target_link_directories(
    he_voting_crypto
    PRIVATE
    "${OpenFHE_LIBDIR}"
)

target_link_libraries(
    he_voting_crypto
    PRIVATE
    ${OpenFHE_SHARED_LIBRARIES}
)

set_target_properties(
    he_voting_crypto
    PROPERTIES
    BUILD_RPATH "${OpenFHE_LIBDIR}"
)
