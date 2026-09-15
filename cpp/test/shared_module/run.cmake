# Installs the static IPC build at BUILD_DIR into a fresh prefix, then builds and
# runs test/shared_module against that prefix alone.
foreach(var BUILD_DIR SOURCE_DIR WORK_DIR C_COMPILER CXX_COMPILER)
    if(NOT DEFINED ${var})
        message(FATAL_ERROR "run.cmake: ${var} is required")
    endif()
endforeach()
if(NOT CONFIG)
    set(CONFIG Release)
endif()
file(REMOVE_RECURSE "${WORK_DIR}")
function(step)
    execute_process(COMMAND ${ARGN} RESULT_VARIABLE rc)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "failed (${rc}): ${ARGN}")
    endif()
endfunction()
step("${CMAKE_COMMAND}" --install "${BUILD_DIR}" --config "${CONFIG}" --prefix "${WORK_DIR}/prefix")
step("${CMAKE_COMMAND}" -S "${SOURCE_DIR}" -B "${WORK_DIR}/build"
    "-DCMAKE_PREFIX_PATH=${WORK_DIR}/prefix" "-DCMAKE_BUILD_TYPE=${CONFIG}"
    "-DCMAKE_C_COMPILER=${C_COMPILER}" "-DCMAKE_CXX_COMPILER=${CXX_COMPILER}")
step("${CMAKE_COMMAND}" --build "${WORK_DIR}/build" --config "${CONFIG}")
step("${WORK_DIR}/build/ipc_shared_module_loader")
