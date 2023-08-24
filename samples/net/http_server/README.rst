.. _http_server:

HTTP server
###########

The HTTP server sample demonstrates how to host a HTTP server on a nRF70 Series device.

.. contents::
   :local:
   :depth: 2

Requirements
************

The sample supports the following development kits:

.. table-from-sample-yaml::

.. include:: /includes/tfm.txt

Overview
********

The sample supports setting and getting the state of LED 1 and 2 on a supported development kit via the default server URL: *http://httpserver.local:8080/led/<1/2>* or *https://httpserver.local:443/led/<1/2>* (TLS).
The server supports both incoming IPv4 and IPv6 connections, but only works on localhost, meaning that the server is not reachable from the open internet.
The sample supports mDNS queries with a hostname set by the :kconfig:option:`CONFIG_NET_HOSTNAME` option.
Depending on the performed HTTP call and state of the device the device will return typical HTTP reponses such as *HTTP/1.1 200 OK* and *HTTP/1.1 400 Bad Request*.

Configuration
*************

The following lists the application-specific configurations used in the sample.
They are located in :file:`samples/net/http_server/Kconfig`.

.. _CONFIG_HTTP_SERVER_SAMPLE_SERVER_PORT:

CONFIG_HTTP_SERVER_SAMPLE_SERVER_PORT
   This configuration option sets the server port for the HTTP server sample.

.. _CONFIG_HTTP_SERVER_SAMPLE_SERVER_PORT_TLS:

CONFIG_HTTP_SERVER_SAMPLE_SERVER_PORT_TLS
   This configuration option sets the server port for the HTTP server sample when using TLS.

.. _CONFIG_HTTP_SERVER_SAMPLE_CLIENTS_MAX:

CONFIG_HTTP_SERVER_SAMPLE_CLIENTS_MAX
   This configuration option sets the maximum number of concurrent clients for the HTTP server sample.

.. _CONFIG_HTTP_SERVER_SAMPLE_SERVER_CERTIFICATE_SEC_TAG:

CONFIG_HTTP_SERVER_SAMPLE_SERVER_CERTIFICATE_SEC_TAG
   This configuration option sets the security tag for the server certificate used in TLS.

.. _CONFIG_HTTP_SERVER_SAMPLE_STACK_SIZE:

CONFIG_HTTP_SERVER_SAMPLE_STACK_SIZE
   This configuration option sets the stack size for the threads used in the HTTP server sample.

.. _CONFIG_HTTP_SERVER_SAMPLE_RECEIVE_BUFFER_SIZE:

CONFIG_HTTP_SERVER_SAMPLE_RECEIVE_BUFFER_SIZE
   This configuration option sets the receive buffer size for the sockets used in the HTTP server sample.

.. include:: /includes/wifi_credentials_shell.txt
.. include:: /includes/wifi_credentials_static.txt

Configuration files
===================

The sample includes pre-configured configuration files for the development kits that are supported:

* :file:`prj.conf` - General configuration file for all devices.
* :file:`boards/nrf7002dk_nrf5340_cpuapp_ns.conf` - Configuration file for the nRF7002 DK.

Files that are located under the :file:`/boards` folder are automatically merged with the :file:`prj.conf` file when you build for the corresponding target.

Building and running
********************

.. |sample path| replace:: :file:`samples/net/http_server`

.. include:: /includes/build_and_run_ns.txt

Testing
=======

|test_sample|

1. |connect_kit|
#. |connect_terminal|
#. Reset your board.
#. Observe that the board connects to the network and is waiting for incoming HTTP connections.
#. Set/get the value of the two supported LEDs by performing HTTP calls to either of the two corresponding URLs. In the following example we are using `HTTPie`_:

.. tabs::

   .. tab:: Non-TLS

      .. code-block:: console

         http PUT http://httpserver.local:8080/led/0 --raw="1"
         http GET http://httpserver.local:8080/led/0

   .. tab:: TLS with server authentication

      .. code-block:: console

         https PUT https://httpserver.local:443/led/0 --raw="1" --verify <sample-path>/credentials/public_certificate.pem
         https GET https://httpserver.local:443/led/0 --verify <sample-path>/credentials/public_certificate.pem

.. rst-class:: numbered-step

Sample output
=============

The following serial UART output is displayed in the terminal emulator when running the sample:

.. code-block:: console

   *** Booting nRF Connect SDK v1.1.0-rc1-15416-gb0a135cfb3a4 ***
   [00:00:00.535,430] <inf> http_server: HTTP Server sample started
   [00:00:00.563,537] <inf> http_server: Network interface brought up
   uart:~$ wifi connect <ssid> <password>
   [00:00:09.973,358] <inf> http_server: Network connected
   [00:00:09.975,708] <inf> http_server: Waiting for IPv6 HTTP(S) connections on port 443, sock 9
   [00:00:09.976,562] <inf> http_server: Waiting for IPv4 HTTP(S) connections on port 443, sock 13
   [00:00:35.173,034] <inf> http_server: [15] Connection from 10.42.0.1 accepted
   [00:00:35.203,247] <inf> http_server: LED 0 state updated to 1

The following serial output is from the terminal window that performs the HTTP calls:

.. code-block:: console

   ➜  ~ https PUT https://httpserver.local:443/led/1 --raw="1" --verify ~/dev/ncs/nrf/samples/net/http_server/credentials/public_certificate.pem
   HTTP/1.1 200 OK

   ➜  ~ https GET https://httpserver.local:443/led/2 --verify ~/dev/ncs/nrf/samples/net/http_server/credentials/public_certificate.pem
   HTTP/1.1 200 OK
   Content-Length: 1

   1

Dependencies
************

This sample uses the following |NCS| and Zephyr libraries:

* :ref:`net_if_interface`
* :ref:`net_mgmt_interface`
* :ref:`http_parser`
