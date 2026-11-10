cmake_minimum_required(VERSION 3.20)

project(ztas LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(ztas
    src/main.cpp
    src/identity/auth_service.cpp
    src/identity/mfa_service.cpp
    src/device/device_registry.cpp
    src/device/device_management_service.cpp
    src/device/device_discovery_service.cpp
    src/device/enrollment_code_service.cpp
    src/authorization/access_service.cpp
    src/policy/policy_client.cpp
    src/audit/audit_logger.cpp
    src/data/secure_data_store.cpp
)

add_executable(secret_hash_tool
    tools/secret_hash_tool.cpp
)

add_executable(provision_devices
    tools/provision_devices.cpp
)

target_include_directories(ztas PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Homebrew deliberately keeps several libraries outside macOS's default CMake
# search paths. Add only installed prefixes, so native macOS setup remains a
# one-command CMake build while Windows continues to use the vcpkg toolchain.
if(APPLE)
    find_program(HOMEBREW_EXECUTABLE brew)
    if(HOMEBREW_EXECUTABLE)
        foreach(package_name cpp-httplib nlohmann-json openssl@3 sqlite)
            execute_process(
                COMMAND ${HOMEBREW_EXECUTABLE} --prefix ${package_name}
                OUTPUT_VARIABLE package_prefix
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
                RESULT_VARIABLE package_result
            )
            if(package_result EQUAL 0)
                list(APPEND CMAKE_PREFIX_PATH "${package_prefix}")
            endif()
        endforeach()
    endif()
endif()

find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

target_link_libraries(ztas PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
    SQLite3::SQLite3
)

target_link_libraries(secret_hash_tool PRIVATE
    OpenSSL::Crypto
)

target_link_libraries(provision_devices PRIVATE
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
)

# cpp-httplib uses Winsock when ZTAS is built natively on Windows.  The
# dependency is implicit on Unix-like platforms, but must be linked explicitly
# by applications using the header-only HTTP implementation on Windows.
if(WIN32)
    # cpp-httplib 0.65+ supports Windows 10 and newer only. MinGW otherwise
    # defaults to an older Windows SDK surface and hides APIs such as CreateFile2.
    target_compile_definitions(ztas PRIVATE
        _WIN32_WINNT=0x0A00
        WINVER=0x0A00
    )
    target_link_libraries(ztas PRIVATE ws2_32)
endif()
