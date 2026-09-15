cmake_minimum_required(VERSION 3.16)
project(ipc_installed_shared_module LANGUAGES C CXX)
find_package(abstraction_ipc CONFIG REQUIRED)
# A shared module linking the installed static archive, the shape of the Node
# addon. The link fails on Linux when the archive holds non-PIC objects.
add_library(ipc_shared_module MODULE module.c)
target_link_libraries(ipc_shared_module PRIVATE abstraction::ipc)
set_target_properties(ipc_shared_module PROPERTIES PREFIX "")
add_executable(ipc_shared_module_loader loader.c)
target_link_libraries(ipc_shared_module_loader PRIVATE ${CMAKE_DL_LIBS})
target_compile_definitions(ipc_shared_module_loader PRIVATE
    MODULE_PATH="$<TARGET_FILE:ipc_shared_module>")
add_dependencies(ipc_shared_module_loader ipc_shared_module)
