#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

if(CONFIG_MPSL AND NOT CONFIG_MPSL_FEM_ONLY)
  add_subdirectory(init)
endif()

if(CONFIG_MPSL_FEM OR CONFIG_MPSL_FEM_PIN_FORWARDER OR CONFIG_MPSL_FEM_API_AVAILABLE)
  add_subdirectory(fem)
endif()

add_subdirectory(cx)

if(CONFIG_MPSL OR CONFIG_MPSL_FEM_ONLY)
  add_subdirectory(hwres)
endif()

if(CONFIG_MPSL_USE_ZEPHYR_PM)
  add_subdirectory(pm)
endif()

if(CONFIG_MPSL_USE_EXTERNAL_CLOCK_CONTROL)
  add_subdirectory(clock_ctrl)
endif()

add_subdirectory_ifdef(CONFIG_MPSL_PIN_DEBUG pin_debug)

function(nrfxlib_mpsl_option_true name option)
  if(${option})
    set(${name} ON PARENT_SCOPE)
  else()
    set(${name} OFF PARENT_SCOPE)
  endif()
endfunction()


  nrfxlib_mpsl_option_true(NRFXLIB_SDC_ENABLED CONFIG_BT_LL_SOFTDEVICE)
  nrfxlib_mpsl_option_true(NRFXLIB_SDC_BUILD_TYPE_LIB CONFIG_BT_LL_SOFTDEVICE_BUILD_TYPE_LIB)
  nrfxlib_mpsl_option_true(NRFXLIB_SDC_HEADERS_INCLUDE CONFIG_BT_LL_SOFTDEVICE_HEADERS_INCLUDE)
  nrfxlib_mpsl_option_true(NRFXLIB_SDC_HEADERS_INCLUDE_PATH_OVERRIDE
    CONFIG_BT_LL_SOFTDEVICE_HEADERS_INCLUDE_PATH_OVERRIDE)

  set(MPSL_SOC "${CONFIG_MPSL_SOC_DIR}" CACHE STRING "" FORCE)
  set(MPSL_FLOAT_TYPE "${CONFIG_MPSL_FLOAT_ABI_DIR}" CACHE STRING "" FORCE)

  set(MPSL_DIR "${ZEPHYR_NRFXLIB_MODULE_DIR}/mpsl")

  add_subdirectory(${MPSL_DIR} ${CMAKE_BINARY_DIR}/mpsl)

  if(NOT TARGET mpsl)
    message(FATAL_ERROR
      "MPSL target was not created. "
      "Check variant and MPSL_DIR settings.")
  endif()

  zephyr_link_libraries(mpsl)
