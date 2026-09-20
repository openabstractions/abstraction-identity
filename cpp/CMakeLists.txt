cmake_minimum_required(VERSION 3.16)
project(abstraction_ipc VERSION 0.1.0 LANGUAGES C CXX)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
add_library(abstraction_ipc src/client.cpp)
add_library(abstraction::ipc ALIAS abstraction_ipc)
# The static archive is linked into shared modules such as the Node addon, and
# Linux links a shared object only from position-independent code. The interface
# property is exported, so a consumer's target agrees with the archive.
set_target_properties(abstraction_ipc PROPERTIES EXPORT_NAME ipc
    POSITION_INDEPENDENT_CODE ON
    INTERFACE_POSITION_INDEPENDENT_CODE ON)
target_compile_features(abstraction_ipc PRIVATE cxx_std_17)
# Platform link requirements come from link-dependencies.txt, the one list Rust
# build.rs also reads from the installed prefix. cxx-runtime entries are supplied
# by the C++ linker CMake consumers already use.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/link-dependencies.txt" abstraction_ipc_link_lines REGEX "^[^#]")
foreach(line IN LISTS abstraction_ipc_link_lines)
    string(REGEX MATCHALL "[^ \t]+" fields "${line}")
    list(LENGTH fields field_count)
    if(NOT field_count EQUAL 3)
        message(FATAL_ERROR "link-dependencies.txt: expected '<platform> <kind> <library>': ${line}")
    endif()
    list(GET fields 0 link_platform)
    list(GET fields 1 link_kind)
    list(GET fields 2 link_name)
    if(link_platform STREQUAL "windows")
        set(link_platform_id Windows)
    elseif(link_platform STREQUAL "linux")
        set(link_platform_id Linux)
    elseif(link_platform STREQUAL "macos")
        set(link_platform_id Darwin)
    else()
        message(FATAL_ERROR "link-dependencies.txt: unknown platform ${link_platform}")
    endif()
    if(link_kind STREQUAL "system")
        target_link_libraries(abstraction_ipc PUBLIC "$<$<PLATFORM_ID:${link_platform_id}>:${link_name}>")
    elseif(NOT link_kind STREQUAL "cxx-runtime")
        message(FATAL_ERROR "link-dependencies.txt: unknown kind ${link_kind}")
    endif()
endforeach()
target_include_directories(abstraction_ipc PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_definitions(abstraction_ipc PRIVATE ABSTRACTION_IPC_BUILD)
if(BUILD_SHARED_LIBS)
    target_compile_definitions(abstraction_ipc PUBLIC ABSTRACTION_IPC_SHARED)
endif()
install(TARGETS abstraction_ipc EXPORT abstraction_ipcTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES link-dependencies.txt DESTINATION ${CMAKE_INSTALL_DATADIR}/abstraction_ipc)
set(config_dir ${CMAKE_INSTALL_LIBDIR}/cmake/abstraction_ipc)
install(EXPORT abstraction_ipcTargets NAMESPACE abstraction:: DESTINATION ${config_dir})
configure_package_config_file(cmake/abstraction_ipcConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/abstraction_ipcConfig.cmake INSTALL_DESTINATION ${config_dir})
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/abstraction_ipcConfigVersion.cmake
    COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/abstraction_ipcConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/abstraction_ipcConfigVersion.cmake DESTINATION ${config_dir})

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    option(ABSTRACTION_IPC_BUILD_TESTS "Build local C consumer tests" ON)
    if(ABSTRACTION_IPC_BUILD_TESTS)
        find_package(Threads REQUIRED)
        add_executable(ipc_c_consumer test/consumer/main.c test/consumer/fixture.cpp)
        target_compile_features(ipc_c_consumer PRIVATE cxx_std_17)
        target_link_libraries(ipc_c_consumer PRIVATE abstraction::ipc Threads::Threads)
        add_executable(ipc_cancellation_consumer test/cancellation/main.cpp test/consumer/fixture.cpp)
        target_compile_features(ipc_cancellation_consumer PRIVATE cxx_std_17)
        target_link_libraries(ipc_cancellation_consumer PRIVATE abstraction::ipc Threads::Threads)
        add_executable(ipc_server_trust test/server_trust/main.c test/server_trust/fixture.cpp)
        target_compile_features(ipc_server_trust PRIVATE cxx_std_17)
        target_link_libraries(ipc_server_trust PRIVATE abstraction::ipc Threads::Threads)
        enable_testing()
        add_executable(ipc_runtime_selection test/runtime_selection/main.cpp)
        target_compile_features(ipc_runtime_selection PRIVATE cxx_std_17)
        target_link_libraries(ipc_runtime_selection PRIVATE abstraction::ipc Threads::Threads)
        add_executable(ipc_frame_errors test/errors/main.cpp)
        target_compile_features(ipc_frame_errors PRIVATE cxx_std_17)
        target_link_libraries(ipc_frame_errors PRIVATE abstraction::ipc)
        add_test(NAME FrameErrors COMMAND ipc_frame_errors)
        set_tests_properties(FrameErrors PROPERTIES TIMEOUT 10)
        add_test(NAME RuntimeSelection COMMAND ipc_runtime_selection)
        set_tests_properties(RuntimeSelection PROPERTIES TIMEOUT 10)
        add_test(NAME ServerTrust COMMAND ipc_server_trust)
        set_tests_properties(ServerTrust PROPERTIES TIMEOUT 20)
        add_test(NAME CConsumer COMMAND ipc_c_consumer)
        set_tests_properties(CConsumer PROPERTIES TIMEOUT 10)
        add_test(NAME CancellationConsumer COMMAND ipc_cancellation_consumer)
        set_tests_properties(CancellationConsumer PROPERTIES TIMEOUT 20)
        # Installs this build's static package and links a shared module against
        # it, as the Node addon does. Unix only: Windows links DLLs from any object.
        if(UNIX AND NOT BUILD_SHARED_LIBS)
            add_test(NAME InstalledStaticSharedModule COMMAND ${CMAKE_COMMAND}
                -DBUILD_DIR=${CMAKE_BINARY_DIR}
                -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/test/shared_module
                -DWORK_DIR=${CMAKE_BINARY_DIR}/shared-module-test
                -DCONFIG=$<CONFIG>
                -DC_COMPILER=${CMAKE_C_COMPILER}
                -DCXX_COMPILER=${CMAKE_CXX_COMPILER}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/test/shared_module/run.cmake)
            set_tests_properties(InstalledStaticSharedModule PROPERTIES TIMEOUT 120)
        endif()
    endif()
endif()
