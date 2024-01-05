.. _http_server:

HTTP server
###########

The HTTP server sample demonstrates how to host an HTTP server that runs on an Internet connected Nordic device via cellular or Wi-Fi.

.. include:: /includes/net_connection_manager.txt

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

Sample supports multiple incoming connections, client ID MAX. State that this is per IP family
Depending on the performed HTTP call and state of the device, the device will return typical HTTP responses such as *HTTP/1.1 200 OK* and *HTTP/1.1 400 Bad Request*.
The sample supports setting and getting of the state of LED 1 and 2 on a supported development kit.
There are key differences between how the sample behaves which depends on the board the sample is built for.
The server supports both incoming IPv4 and IPv6 connections


The following table explains some of these differences:

Access:
LTE - global (depends on a SIM card with an associated static IP by the mobile operator)
WI-Fi - local network, supports Multicast Domain Name Service (mDNS) and accessible by other devices on the local network.
HTTP URL - httpserver.local
Security - TLS with server authentication,




the URL in which the device is accessible dependends on the type of build and the board the sample is built for:




 * LTE


Explain the difference in behavior between LTE and WIFI

Cellular
=======

On cellular you are dependent on a SIM card with a fixed/static IP to be reachable. Telecom operators typically provide these types of SIM cards.
Important to verify that you actually get IPv6 on LTE
Some thoughts regarding PSM vs EDRX and how to set that
SIM card dependent, etc...

To ensure that the LTE device is responsive PSM, edrx needs to be disabled or set to the desired level of responsibility.
Have in mind that its not nessecarily the case that the network caches packets sent to the device when it sleeps.
CONFIG_LTE_PSM_REQ=n


* :kconfig:option:`CONFIG_PDN_DEFAULTS_OVERRIDE` - Used for manual configuration of the APN.
  Set the option to ``y`` to override the default PDP context configuration.
* :kconfig:option:`CONFIG_PDN_DEFAULT_APN` - Used for manual configuration of the APN.
  An example is ``apn.example.com``.



  To verify that the device gets the same IP every time you can enable the AT host library and issue the CGDCONT at command to verify.
CONFIG_AT_HOST_LIBRARY=y
CONFIG_UART_INTERRUPT_DRIVEN=y

Some output here. Add TLS support for nrf91

Write that common name match is not needed and that the server certificate common name needs to match
Can disable this check,

Recommended to generate device certificates when exposed on the internet

Write that MBEDTLS is running on application core and that the certificates are exposed.

/* Run the Zephyr Native TLS stack (MBed TLS) in the application core instead of
		 * using the TLS stack on the modem.
		 * This is needed because the modem does not support TLS in server mode.
		 *
		 * This is done by using (SOCK_STREAM | SOCK_NATIVE_TLS) as socket type when
		 * building for a nRF91 Series board.
		 */

Wi-Fi
=====

.. The sample supports setting and getting the state of LED 1 and 2 on a supported development kit via the default server URL: *http://httpserver.local:80/led/<1/2>* or *https://httpserver.local:443/led/<1/2>* (TLS).
.. The server supports both incoming IPv4 and IPv6 connections, but only works on the local network for Wi-Fi, meaning that the server is not reachable from the open internet.
The sample supports mDNS queries with a hostname set by the :kconfig:option:`CONFIG_NET_HOSTNAME` option.
CONFIG_MDNS_RESPONDER_LOG_LEVEL_DBG=y or use net IPv6 / net ipv4 command

Add instructions on how to use IPv6.
 - Enable IPv6 in router settings, passthrough
 - Find IPv6 address using net ipv6 command
 - Specify IPv6 address in HTTP request: http PUT 'http://[2001:8c0:5140:895:f6ce:36ff:fe00:1970]:80/led/1' --raw="1"






Security
========

openssl genpkey -algorithm RSA -out device.key
openssl req -new -key device.key -out device.csr (SNI much match the one for the public server certificate)
openssl x509 -req -in device.csr -CA ../public_certificate.pem -CAkey ../private_key.pem -CAcreateserial -out device.crt -days 365 (sign using public certificate)
https --debug GET https://httpserver.local:443/led/1 --verify ~/dev/ncs/nrf/samples/net/http_server/credentials/public_certificate.pem --cert ~/dev/ncs/nrf/samples/net/http_server/credentials/client_certificate/device.crt --cert-key ~/dev/ncs/nrf/samples/net/http_server/credentials/client_certificate/device.key

Require peer verification by setting
:kconfig:option:`CONFIG_HTTP_SERVER_SAMPLE_PEER_VERIFICATION_REQUIRE`

Since you cannot use the local hostname when connecting with the you need to generate a new self-signed public certificate and provision to the MBED TLS stack along with the generated server private key.

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
* :file:`boards/nrf9161dk_nrf9161_ns.conf` - Configuration file for the nRF9161 DK.
* :file:`boards/nrf9160dk_nrf9160_ns.conf` - Configuration file for the nRF9160 DK.
* :file:`boards/thingy91_nrf9160_ns.conf` - Configuration file for the Thingy:91.

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

Use curl instaed and show how to use ipv6


   .. tab:: Non-TLS

      .. code-block:: console

         Wi-Fi

         http PUT http://httpserver.local:80/led/1 --raw="1"
         http GET http://httpserver.local:80/led/1

         Cellular

         http PUT http://<ip>:80/led/1 --raw="1"
         http GET http://<ip>:80/led/1

   .. tab:: TLS with server authentication

      .. code-block:: console

         https PUT https://httpserver.local:443/led/1 --raw="1" --verify <sample-path>/credentials/public_certificate.pem
         https GET https://httpserver.local:443/led/1 --verify <sample-path>/credentials/public_certificate.pem

   .. tab:: TLS without authentication (When using IP, hostname mismatch, can solve this by regeneration certificates (instructions) with correct IP as hostname)

      .. code-block:: console

         https GET https://<ip>:443/led/1 --verify=no

.. rst-class:: numbered-step

Sample output
=============

The following serial UART output is displayed in the terminal emulator when running the sample:

Wi-Fi

.. code-block:: console

   Replace and use Wifi cred

Cellular

.. code-block:: console

   Replace

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
* :ref:`Connection Manager <zephyr:conn_mgr_overview>`
