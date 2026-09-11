cmake_minimum_required(VERSION 3.16)
project(abstraction_ipc VERSION 0.1.0 LANGUAGES C CXX)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
add_library(abstraction_ipc src/client.cpp)
add_library(abstraction::ipc ALIAS abstraction_ipc)
set_target_properties(abstraction_ipc PROPERTIES EXPORT_NAME ipc)
target_compile_features(abstraction_ipc PRIVATE cxx_std_17)
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
        enable_testing()
        add_test(NAME CConsumer COMMAND ipc_c_consumer)
        set_tests_properties(CConsumer PROPERTIES TIMEOUT 10)
    endif()
endif()
