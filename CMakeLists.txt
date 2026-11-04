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
    src/authorization/access_service.cpp
    src/policy/policy_client.cpp
    src/audit/audit_logger.cpp
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

find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

target_link_libraries(ztas PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
)

target_link_libraries(secret_hash_tool PRIVATE
    OpenSSL::Crypto
)

target_link_libraries(provision_devices PRIVATE
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
)
