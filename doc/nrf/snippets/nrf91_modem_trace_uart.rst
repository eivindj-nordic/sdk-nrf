.. _nrf91_modem_trace_uart_snippet:

nRF91 modem tracing with UART backend
#####################################

The snippet is tailored for tracing on the nRF91-DKs but can work with other applications as well.
It enables the :kconfig:option:`CONFIG_NRF_MODEM_LIB_TRACE` Kconfig option and chooses the
Zephyr UART driver for the backend, with necessary Kconfig options. The snippet also enables
the `uart1` peripheral with a baudrate of 1 Mbaud and hardware flow control enabled.
If this configuration does not match your requirements, you can add a snippet or
Kconfig and device tree overlays to your application with the desired setup.
To enable modem tracing with the UART trace backend on a nRF91 device, add the
``nrf91-modem-trace-uart`` snippet to the build configuration.
This can be done one of the following ways:

With west
*********
To add the modem trace uart snippet when building an application with west, add

``-S nrf91-modem-trace-uart``

to the build options.

With cmake
**********
To add the modem trace uart snippet when building an application with cmake, add

``-DSNIPPET="nrf91-modem-trace-uart" [...]``

to the CMake arguments.

See :ref:`snippets` for more details on snippets in general.
