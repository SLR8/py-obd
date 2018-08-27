# -*- coding: utf-8 -*-

########################################################################
#                                                                      #
# python-OBD: A python OBD-II serial module derived from pyobd         #
#                                                                      #
# Copyright 2004 Donour Sizemore (donour@uchicago.edu)                 #
# Copyright 2009 Secons Ltd. (www.obdtester.com)                       #
# Copyright 2009 Peter J. Creath                                       #
# Copyright 2016 Brendan Whitfield (brendan-w.com)                     #
# Copyright 2018 AutoPi.io ApS (support@autopi.io)                     #
#                                                                      #
########################################################################
#                                                                      #
# elm327.py                                                            #
#                                                                      #
# This file is part of python-OBD (a derivative of pyOBD)              #
#                                                                      #
# python-OBD is free software: you can redistribute it and/or modify   #
# it under the terms of the GNU General Public License as published by #
# the Free Software Foundation, either version 2 of the License, or    #
# (at your option) any later version.                                  #
#                                                                      #
# python-OBD is distributed in the hope that it will be useful,        #
# but WITHOUT ANY WARRANTY; without even the implied warranty of       #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        #
# GNU General Public License for more details.                         #
#                                                                      #
# You should have received a copy of the GNU General Public License    #
# along with python-OBD.  If not, see <http://www.gnu.org/licenses/>.  #
#                                                                      #
########################################################################

import re
import serial
import time
import logging

from timeit import default_timer as timer
from ..protocols import *
from ..utils import OBDStatus


logger = logging.getLogger(__name__)


########################################################################
# Protocol definitions
########################################################################

class SAE_J1850_PWM(LegacyProtocol):
    NAME = "SAE J1850 PWM"
    ID = "1"
    def __init__(self, lines_0100):
        LegacyProtocol.__init__(self, lines_0100)

class SAE_J1850_VPW(LegacyProtocol):
    NAME = "SAE J1850 VPW"
    ID = "2"
    def __init__(self, lines_0100):
        LegacyProtocol.__init__(self, lines_0100)

class ISO_9141_2(LegacyProtocol):
    NAME = "ISO 9141-2"
    ID = "3"
    def __init__(self, lines_0100):
        LegacyProtocol.__init__(self, lines_0100)

class ISO_14230_4_5baud(LegacyProtocol):
    NAME = "ISO 14230-4 (KWP 5BAUD)"
    ID = "4"
    def __init__(self, lines_0100):
        LegacyProtocol.__init__(self, lines_0100)

class ISO_14230_4_fast(LegacyProtocol):
    NAME = "ISO 14230-4 (KWP FAST)"
    ID = "5"
    def __init__(self, lines_0100):
        LegacyProtocol.__init__(self, lines_0100)

class ISO_15765_4_11bit_500k(CANProtocol):
    NAME = "ISO 15765-4 (CAN 11/500)"
    ID = "6"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=11)

class ISO_15765_4_29bit_500k(CANProtocol):
    NAME = "ISO 15765-4 (CAN 29/500)"
    ID = "7"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=29)

class ISO_15765_4_11bit_250k(CANProtocol):
    NAME = "ISO 15765-4 (CAN 11/250)"
    ID = "8"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=11)

class ISO_15765_4_29bit_250k(CANProtocol):
    NAME = "ISO 15765-4 (CAN 29/250)"
    ID = "9"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=29)

class SAE_J1939(CANProtocol):
    NAME = "SAE J1939 (CAN 29/250)"
    ID = "A"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=29)


########################################################################
# Interface implementation
########################################################################

class ELM327(object):
    """
    Handles communication with the ELM327 adapter.
    """

    ELM_PROMPT = b'\r>'

    SUPPORTED_PROTOCOLS = {
        #"0" : None, # Automatic Mode. This isn't an actual protocol. If the
                     # ELM reports this, then we don't have enough
                     # information. see auto_protocol()
        "1" : SAE_J1850_PWM,
        "2" : SAE_J1850_VPW,
        "3" : ISO_9141_2,
        "4" : ISO_14230_4_5baud,
        "5" : ISO_14230_4_fast,
        "6" : ISO_15765_4_11bit_500k,
        "7" : ISO_15765_4_29bit_500k,
        "8" : ISO_15765_4_11bit_250k,
        "9" : ISO_15765_4_29bit_250k,
        "A" : SAE_J1939,
        #"B" : None, # user defined 1
        #"C" : None, # user defined 2
    }

    # Used as a fallback, when ATSP0 doesn't cut it
    TRY_PROTOCOL_ORDER = [
        "6", # ISO_15765_4_11bit_500k
        "8", # ISO_15765_4_11bit_250k
        "1", # SAE_J1850_PWM
        "7", # ISO_15765_4_29bit_500k
        "9", # ISO_15765_4_29bit_250k
        "2", # SAE_J1850_VPW
        "3", # ISO_9141_2
        "4", # ISO_14230_4_5baud
        "5", # ISO_14230_4_fast
        "A", # SAE_J1939
    ]

    # 38400, 9600 are the possible boot bauds (unless reprogrammed via
    # PP 0C).  19200, 38400, 57600, 115200, 230400, 500000 are listed on
    # p.46 of the ELM327 datasheet.
    #
    # Once pyserial supports non-standard baud rates on platforms other
    # than Linux, we'll add 500K to this list.
    #
    # We check the the default baud rate first, then go fastest to
    # slowest, on the theory that anyone who's using a slow baud rate is
    # going to be less picky about the time required to detect it.
    TRY_BAUDRATES = [9600, 576000, 230400, 115200, 57600, 38400, 19200]

    # OBD functional address
    OBD_HEADER = "7DF" 


    class Decorators(object):

        @staticmethod
        def ensure_obd_mode(func):

            def decorator(self, *args, **kwargs):

                # Ensure OBD header is set
                self.set_header(self.OBD_HEADER)

                # Ensure CAN automatic formatting is enabled
                self.set_can_auto_format(True)

                return func(self, *args, **kwargs)

            return decorator


    def __init__(self):
        """
        Initializes interface instance.
        """

        self._status           = OBDStatus.NOT_CONNECTED
        self._port             = None
        self._protocol         = UnknownProtocol([])
        self._is_echo          = True
        self._header           = self.OBD_HEADER
        
        self._can_auto_format  = True
        self._can_monitor_mode = 0


    def open(self, port, baudrate, protocol, timeout=10, is_echo=True):
        """
        Opens serial connection and initializes ELM327 interface.
        """

        logger.info("Opening interface connection: Port={:}, Baudrate={:}, Protocol={:}".format(
            port,
            "auto" if baudrate is None else baudrate,
            "auto" if protocol is None else protocol
        ))

        # Open serial connection
        try:
            self._port = serial.Serial(port,
                                       parity   = serial.PARITY_NONE,
                                       stopbits = 1,
                                       bytesize = 8,
                                       timeout  = timeout)  # Seconds
        except:
            logger.exception("Failed to open serial connection")
            raise

        # Set the ELM's baudrate
        try:
            self.set_baudrate(baudrate)
        except:
            logger.exception("Failed to set baudrate of serial connection")
            self.close()
            raise

        # Configure ELM settings
        try:

            # Get ID
            res = self.send(b"ATI", delay=1)  # Wait 1 second for ELM to initialize
            # Return data can be junk, so don't bother checking

            # Set echo on/off
            res = self.send(b"ATE{:d}".format(is_echo))
            if not self._is_ok(res, expect_echo=True):
                raise Exception("Invalid response when setting echo '{:}': {:}".format(is_echo, res))
            else:
                self._is_echo = is_echo

            # Set headers on
            res = self.send(b"ATH1")
            if not self._is_ok(res):
                raise Exception("Invalid response when enabling headers: {:}".format(res))

            # Set line feeds off
            res = self.send(b"ATL0")
            if not self._is_ok(res):
                raise Exception("Invalid response when disabling line feeds: {:}".format(res))

        except:
            logger.exception("Failed to configure ELM settings")
            self.close()
            raise

        # By now, we've successfuly communicated with the ELM, but not the car
        self._status = OBDStatus.ELM_CONNECTED

        # Try to communicate with the car, and load the correct protocol parser
        try:
            self.set_protocol(protocol)
        except:
            logger.exception("Unable to set protocol")
            return
            
        # We're now sucessfully connected to the car
        self._status = OBDStatus.CAR_CONNECTED

        logger.info("Connected successfully to car: Port={:}, Baudrate={:}, Protocol={:}".format(
            port,
            self._port.baudrate,
            self._protocol.ID,
        ))


    def close(self):
        """
        Closes connection to ELM327 interface.
        """

        self._status = OBDStatus.NOT_CONNECTED
        
        if self._port is not None:
            logger.info("Closing serial connection")

            self._port.close()
            self._port = None


    def connection_info(self):
        return {
            "port": self._port.portstr,
            "baudrate": self._port.baudrate
        } if self._port else {}


    def status(self):
        return self._status


    def protocol(self):
        return self._protocol


    def protocol_info(self):
        return {
            "id": self._protocol.ID,
            "name": self._protocol.NAME
        } if self._protocol else {}


    def ecus(self):
        return self._protocol.ecu_map.values() if self._protocol else []


    def set_baudrate(self, baudrate):
        if baudrate is None:
            
            # When connecting to pseudo terminal, don't bother with auto baud
            if self._port.portstr.startswith("/dev/pts"):
                logger.warning("Detected pseudo terminal, skipping baudrate setup")
                return
            
            # Autodetect baudrate using default choices list
            self._auto_baudrate(self.TRY_BAUDRATES)

        elif isinstance(baudrate, list):

            # Autodetect baudrate using given choices list
            self._auto_baudrate(baudrate)

        else:

            # Create a list of choices with given baudrate as first entry
            choices = list(self.TRY_BAUDRATES)
            choices.remove(baudrate)
            choices.insert(0, baudrate)

            self._auto_baudrate(choices)


    def supported_protocols(self):
        return self._SUPPORTED_PROTOCOLS


    def set_protocol(self, protocol):
        if protocol is None:

            # Autodetect protocol
            self._auto_protocol()

        else:

            # Validate specified protocol 
            if protocol not in self.supported_protocols():
                raise Exception("Unsupported protocol '{:}'".format(protocol))

            # Set explicit protocol
            self._manual_protocol(protocol)


    def set_header(self, value):
        """
        Set header.
        """

        if value == self._header:
            return

        res = self.send(b"ATSH" + value.encode())
        if not self._is_ok(res):
            raise Exception("Invalid response when setting header '{:}': {:}".format(value, res))

        logger.info("Changed header from '{:}' to '{:}'".format(self._header, value))
        self._header = value


    def set_can_auto_format(self, value):
        """
        Enable/disable CAN automatic formatting.
        """

        if value == self._can_auto_format:
            return

        res = self.send(b"ATCAF" + str(int(value)).encode())
        if not self._is_ok(res):
            raise Exception("Invalid response when setting CAN automatic formatting '{:}': {:}".format(value, res))

        logger.info("Changed CAN automatic formatting from '{:}' to '{:}'".format(self._can_auto_format, value))
        self._can_auto_format = value


    @Decorators.ensure_obd_mode
    def query(self, cmd, parse=False):
        """
        Used to service all OBDCommands.

        Sends the given command string, and if requested
        parses the response lines with the protocol object.

        An empty command string will re-trigger the previous command.

        Returns a list of parsed Message objects or raw response lines.
        """

        lines = self.send(cmd)

        # Parse using protocol if requested
        if parse:
            messages = self._protocol(lines)
            return messages
        
        return lines


    def send(self, cmd, delay=None, interrupt_delay=None):
        """
        Send raw command string.

        Will write the given string, no questions asked.
        Returns read result (a list of line strings) after an optional delay.
        """

        self._write(cmd)

        if delay is not None:
            logger.debug("Wait %d seconds" % delay)
            time.sleep(delay)

        lines = self._read(interrupt_delay=interrupt_delay)

        # Get rid of echo if present
        if self._is_echo and len(lines) > 0:

            # Sanity check if echo matches sent command
            if not self._has_message(lines, "NO DATA") and cmd != lines[0]:
                logger.warning("Sent command does not match echo: '{:}' != '{:}'".format(cmd, lines[0]))

            lines = lines[1:]

        return lines


    def _auto_baudrate(self, choices):
        """
        Detect the baud rate at which a connected ELM32x interface is operating.
        """

        # Before we change the timout, save the "normal" value
        timeout = self._port.timeout
        self._port.timeout = 0.1  # We're only talking with the ELM, so things should go quickly

        try:
            for baudrate in choices:
                self._port.baudrate = baudrate
                self._port.flushInput()
                self._port.flushOutput()

                # Send a nonsense command to get a prompt back from the scanner
                # (an empty command runs the risk of repeating a dangerous command)
                # The first character might get eaten if the interface was busy,
                # so write a second one (again so that the lone CR doesn't repeat
                # the previous command)
                self._port.write(b"\x7F\x7F\r\n")
                self._port.flush()

                res = self._port.read(1024)
                logger.debug("Response from baudrate choice '%d': %s" % (baudrate, repr(res)))

                # Watch for the prompt character
                if res.endswith(self.ELM_PROMPT):
                    logger.info("Choosing baudrate '%d'" % baudrate)

                    return

            raise Exception("Unable to automatically find baudrate from given choices")
        finally:
            self._port.timeout = timeout  # Reinstate our original timeout


    def _manual_protocol(self, protocol):

        # Change protocol
        res = self.send(b"ATTP" + protocol.encode())
        if not self._is_ok(res):
            raise Exception("Invalid response when manually changing to protocol '{:}': {:}".format(protocol, res))

        # Verify protocol connectivity
        r0100 = self.query(b"0100")
        if self._has_message(r0100, "UNABLE TO CONNECT", "CAN ERROR"):
            self._protocol = self.supported_protocols()[protocol]([])
            raise Exception("Unable to verify connectivity of protocol '{:}': {:}".format(protocol, r0100))

        # Verify protocol changed
        res = self.send(b"ATDPN")
        if not self._has_message(res, protocol):
            raise Exception("Manually changed protocol '{:}' does not match currently active protocol '{:}'".format(protocol, res))

        # Initialize protocol parser
        self._protocol = self.supported_protocols()[protocol](r0100)
        logger.info("Protocol '{:}' set manually: {:}".format(protocol, self._protocol))


    def _auto_protocol(self):
        """
        Attempts communication with the car.
        Upon success, the appropriate protocol parser is loaded.
        """

        # Try the ELM's auto protocol mode
        res = self.send(b"ATSP0")

        # First command search protocols
        r0100 = self.query(b"0100")

        # Get protocol number
        res = self.send(b"ATDPN")
        if len(res) != 1:
            log.error("Invalid response when getting protocol number: {:}".format(res))
            raise Exception("Failed to retrieve current protocol")

        pro = res[0]  # Grab the first (and only) line returned
        # Suppress any "automatic" prefix
        pro = pro[1:] if (len(pro) > 1 and pro.startswith("A")) else pro

        # Check if the protocol is supported
        if pro in self.supported_protocols():

            # Jackpot, instantiate the corresponding protocol handler
            self._protocol = self.supported_protocols()[pro](r0100)
            logger.info("Protocol '{:}' set automatically: {:}".format(pro, self._protocol))

            return

        # Unknown protocol is likely because not all adapter/car combinations work
        # in "auto" mode. Some respond to ATDPN responded with "0".
        logger.info("ELM responded with an unknown/unsupported protocol: {:}".format(pro))

        # Trying them one-by-one
        for pro in self.TRY_PROTOCOL_ORDER:
            res = self.send(b"ATTP" + p.encode())

            r0100 = self.query(b"0100")
            if not self._has_message(r0100, "UNABLE TO CONNECT", "CAN ERROR"):

                # Success, found a valid protocol
                self._protocol = self.supported_protocols()[pro](r0100)
                logger.info("Protocol '{:}' set automatically using try list: {:}".format(pro, self._protocol))

                return

        # If we've come this far, then we have failed
        raise Exception("Unable to determine protocol automatically")


    def _write(self, cmd):
        """
        Low-level function to write a string to the port.
        """

        if not self._port or not self._port.is_open:
            raise Exception("Cannot write when serial connection is not open")

        cmd += b"\r\n"  # Terminate
        logger.info("Write: " + repr(cmd))

        self._port.flushInput()  # Dump everything in the input buffer
        self._port.write(cmd)  # Turn the string into bytes and write
        self._port.flush()  # Wait for the output buffer to finish transmitting


    def _read(self, interrupt_delay=None):
        """
        Low-level read function.

        Accumulates characters until the prompt character is seen.
        Returns a list of [/r/n] delimited strings.
        """

        if not self._port or not self._port.is_open:
            raise Exception("Cannot read when serial connection is not open")

        buffer = bytearray()
        start = timer()

        while True:

            # Retrieve as much data as possible
            data = self._port.read(self._port.in_waiting or 1)

            # If nothing was recieved
            if not data:
                logger.warning("No data received within timeout of {:d} seconds".format(self._port.timeout))

                # Only break if no interrupt character is pending
                if interrupt_delay == None:
                    break

            buffer.extend(data)

            # End on chevron + carriage return (ELM prompt characters)
            if buffer.endswith(self.ELM_PROMPT):
                break

            # Check if it is time to send an interrupt character
            if interrupt_delay != None and (timer() - start) >= interrupt_delay:
                logger.info("Sending interrupt character during read")

                self._port.write(b"\x7F")
                interrupt_delay = None

        # Log, and remove the "bytearray(   ...   )" part
        logger.info("Read: " + repr(buffer)[10:-1])

        # Clean out any null characters
        buffer = re.sub(b"\x00", b"", buffer)

        # Remove the prompt characters
        if buffer.endswith(self.ELM_PROMPT):
            buffer = buffer[:-len(self.ELM_PROMPT)]

        # Convert bytes into a standard string
        string = buffer.decode()

        # Splits into lines while removing empty lines and trailing spaces
        lines = [s.strip() for s in re.split("[\r\n]", string) if bool(s)]

        return lines


    def _is_ok(self, lines, expect_echo=False):
        if not lines:
            return False

        if self._is_echo or expect_echo:
            return self._has_message(lines, "OK")

        return len(lines) == 1 and lines[0] == "OK"


    def _has_message(self, lines, *args):
        for line in lines:
            for arg in args:
                if arg in line:
                    return True

        return False

