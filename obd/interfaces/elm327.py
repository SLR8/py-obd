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

import collections
import logging
import re
import serial
import time

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


class ELM327Error(Exception):

    def __init__(self, *args, **kwargs):
        self.code = kwargs.pop("code", None)
        super(Exception, self).__init__(*args, **kwargs)


class ELM327(object):
    """
    Handles communication with the ELM327 adapter.
    """

    PROMPT = b"\r>"
    OK = b"OK"
    ERRORS = {
        "?":                  "Unsupported command",
        "BUS BUSY":           "Too much activity on bus",
        "BUS ERROR":          "Invalid signal detected on bus",
        "CAN ERROR":          "CAN sending or receiving failed",
        "DATA ERROR":         "Incorrect response from vehicle",
        "FB ERROR":           "Problem with feedback signal",
        "UNABLE TO CONNECT":  "Unable to connect because no supported protocol found",
        "NO DATA":            "No response from vehicle within timeout",
        "BUFFER FULL":        "Internal RS232 transmit buffer is full",
        "ACT ALERT":          "No RS232 or OBD activity for some time",
        "LV RESET":           "Low voltage reset",
        "LP ALERT":           "Low power (standby) mode in 2 seconds",
        "STOPPED":            "Operation interrupted by a received RS232 character",
    }

    SUPPORTED_PROTOCOLS = collections.OrderedDict({
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
    })

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
    # We check the two default baud rates first, then go fastest to
    # slowest, on the theory that anyone who's using a slow baud rate is
    # going to be less picky about the time required to detect it.
    TRY_BAUDRATES = [38400, 9600, 230400, 115200, 57600, 38400, 19200]

    # OBD functional address
    OBD_HEADER = "7DF" 

    # Programmable parameter IDs
    PP_ATH = "01"
    PP_ATE = "09"


    class Decorators(object):

        @staticmethod
        def ensure_obd_mode(func):

            def decorator(self, *args, **kwargs):

                # Ensure OBD header is set
                self.set_header(self.OBD_HEADER)

                # Ensure CAN automatic formatting is enabled
                self.set_can_auto_format(True)

                # Ensure responses are turned on
                self.set_expect_responses(True)

                return func(self, *args, **kwargs)

            return decorator


    def __init__(self, port, timeout=10, status_callback=None):
        """
        Initializes interface instance.
        """

        self._status              = OBDStatus.NOT_CONNECTED
        self._status_callback     = status_callback
        self._protocol            = UnknownProtocol([])

        # Default values for settings
        self._echo_off            = False
        self._print_headers       = False
        self._expect_responses    = True
        self._header              = self.OBD_HEADER
        self._can_auto_format     = True
        self._can_monitor_mode    = 0

        self._port = serial.Serial(parity   = serial.PARITY_NONE,
                                   stopbits = 1,
                                   bytesize = 8,
                                   timeout  = timeout)  # Seconds
        self._port.port = port


    def open(self, baudrate, protocol, echo_off=True, print_headers=True):
        """
        Opens serial connection and initializes ELM327 interface.
        """

        logger.info("Opening interface connection: Port={:}, Baudrate={:}, Protocol={:}".format(
            self._port.port,
            "auto" if baudrate is None else baudrate,
            "auto" if protocol is None else protocol
        ))

        # Open serial connection
        try:
            self._port.open()
        except:
            logger.exception("Failed to open serial connection")

            # Remember to report back status
            self._trigger_status_callback()

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

            # Check if ready
            res = self.send(b"ATI", delay=1, filtering=False)  # Wait 1 second for ELM to initialize
            # Return data can be junk, so don't bother checking

            # Determine if echo is on or off
            res = self.send(b"ATI", filtering=False)
            self._echo_off = not self._has_message(res, "ATI")

            # Load current settings from programmable parameters
            params = self._get_pps()

            warm_reset = False

            # Set echo on/off
            if self._ensure_pp(params[self.PP_ATE], "FF" if echo_off else "00", default="00"):
                warm_reset = True
            # Echo has maybe been changed manually (using ATE0/1) - reset to load setting from PP
            elif self._echo_off != echo_off:
                warm_reset = True

            # Enable/disable printing of headers
            if self._ensure_pp(params[self.PP_ATH], "00" if print_headers else "FF", default="FF"):
                warm_reset = True

            # Perform warm reset if changes have been made
            if warm_reset:
                logger.info("Performing warm reset after updating programmable parameter(s)")
                self.warm_reset()

            # Finally update setting variables with possible new values
            self._echo_off = echo_off
            self._print_headers = print_headers

        except:
            logger.exception("Failed to configure ELM settings")

            self.close()

            raise

        # By now, we've successfuly communicated with the ELM, but not the car
        self._status = OBDStatus.ITF_CONNECTED

        # Remember to report back status
        self._trigger_status_callback()

        # Try to communicate with the car, and load the correct protocol parser
        try:
            self.set_protocol(protocol)
        except ELM327Error:
            logger.exception("Unable to set protocol '{:}'".format(protocol))

            return

        logger.info("Connected successfully to vehicle: Port={:}, Baudrate={:}, Protocol={:}".format(
            self._port.port,
            self._port.baudrate,
            self._protocol.ID,
        ))


    def close(self):
        """
        Closes connection to interface.
        """

        self._status = OBDStatus.NOT_CONNECTED
        
        if self._port is not None:
            logger.info("Closing serial connection")

            self._port.close()

        # Report status changed
        self._trigger_status_callback()


    def reopen(self):
        """
        Closes and opens connection again to interface.
        """

        self.close()
        self.open(
            self._port.baudrate if self._port else None,
            self._protocol.ID if self._protocol else None
        )


    def warm_reset(self):
        """
        Soft reset that keeps the user selected baud rate.
        """

        self.send(b"ATWS")


    def reset(self):
        """
        Full reset. Serial connection is closed and re-opened.
        """

        self.send(b"ATZ")
        self.reopen()


    def connection(self):
        return self._port


    def status(self):
        return self._status


    def protocol(self):
        return self._protocol


    def ecus(self):
        return self._protocol.ecu_map.values() if self._protocol else []


    def set_baudrate(self, baudrate):
        if baudrate == None:
            
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


    def set_protocol(self, ident, **kwargs):

        # Validate protocol if given
        if ident != None and ident not in self.supported_protocols():
            raise ELM327Error("Unsupported protocol '{:}'".format(ident))

        try:

            # Autodetect protocol
            if ident == None:
                self._protocol = self._auto_protocol()
                self._protocol.autodetected = True

                logger.info("Protocol '{:}' set automatically: {:}".format(self._protocol.ID, self._protocol))

            # Set explicit protocol
            else:
                self._protocol = self._manual_protocol(ident, **kwargs)
                self._protocol.autodetected = False

                logger.info("Protocol '{:}' set manually: {:}".format(self._protocol.ID, self._protocol))

            # Update overall status
            self._status = OBDStatus.BUS_CONNECTED

            # Report status changed
            self._trigger_status_callback(protocol=self._protocol)

        except:
            self._protocol = UnknownProtocol([])

            # Update overall status
            if self._status == OBDStatus.BUS_CONNECTED:
                self._status = OBDStatus.ITF_CONNECTED

                # Report status changed
                self._trigger_status_callback()

            raise


    def set_expect_responses(self, value):
        """
        Turn responses on or off
        """

        if value == self._expect_responses:
            return

        res = self.send(b"ATR" + str(int(value)).encode())
        if not self._is_ok(res):
            raise ELM327Error("Invalid response when setting responses '{:}': {:}".format(value, res))

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Changed responses from '{:}' to '{:}'".format(self._expect_responses, value))

        self._expect_responses = value


    def set_header(self, value):
        """
        Set header value to use when sending request(s).
        """

        if value == self._header:
            return

        res = self.send(b"ATSH" + value.encode())
        if not self._is_ok(res):
            raise ELM327Error("Invalid response when setting header '{:}': {:}".format(value, res))

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Changed header from '{:}' to '{:}'".format(self._header, value))

        self._header = value


    def set_can_auto_format(self, value):
        """
        Enable/disable CAN automatic formatting.
        """

        if value == self._can_auto_format:
            return

        res = self.send(b"ATCAF" + str(int(value)).encode())
        if not self._is_ok(res):
            raise ELM327Error("Invalid response when setting CAN automatic formatting '{:}': {:}".format(value, res))

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Changed CAN automatic formatting from '{:}' to '{:}'".format(self._can_auto_format, value))

        self._can_auto_format = value


    @Decorators.ensure_obd_mode
    def query(self, cmd, parse=True):
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


    def send(self, cmd, delay=None, filtering=True, interrupt_delay=None):
        """
        Send raw command string.

        Will write the given string, no questions asked.
        Returns read result (a list of line strings) after an optional delay.
        """

        self._write(cmd)

        if delay is not None:

            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Wait %d seconds" % delay)

            time.sleep(delay)

        lines = self._read(interrupt_delay=interrupt_delay)

        if not filtering:
            return lines

        # Filter out echo if present
        if not self._echo_off and len(lines) > 0:

            # Sanity check if echo matches sent command
            if cmd != lines[0]:
                logger.warning("Sent command does not match echo: '{:}' != '{:}'".format(cmd, lines[0]))
            else:
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

                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Response from baudrate choice '%d': %s" % (baudrate, repr(res)))

                # Watch for the prompt character
                if res.endswith(self.PROMPT):
                    logger.info("Choosing baudrate '%d'" % baudrate)

                    return

            raise ELM327Error("Unable to automatically find baudrate from given choices")
        finally:
            self._port.timeout = timeout  # Reinstate our original timeout


    def _verify_protocol(self, ident, force=False):
        ret = []

        ignore_lines = ["SEARCHING...", "NO DATA"]
        for line in self.query(b"0100", parse=False):

            # Skip ignore lines
            if line in ignore_lines:
                continue

            # Check if valid hex
            try:
                int(line.replace(" ", ""), 16)
            except ValueError:
                err = self.ERRORS.get(line, "Invalid non-hex response: {:}".format(line))

                msg = "Unable to verify connectivity of protocol '{:}': {:}".format(ident, err)
                if force:
                    logger.warning(msg)

                    return []
                else:
                    raise ELM327Error(msg)

            ret.append(line)

        if not ret:
            logger.warning("No data received when trying to verify connectivity of protocol '{:}'".format(ident))

        return ret


    def _manual_protocol(self, ident, verify=True):

        # Change protocol
        res = self.send(b"ATTP" + ident.encode())
        if not self._is_ok(res):
            raise ELM327Error("Invalid response when manually changing to protocol '{:}': {:}".format(ident, res))

        # Verify protocol connectivity
        res_0100 = self._verify_protocol(ident, force=not verify)

        # Verify protocol changed
        res = self.send(b"ATDPN")
        if not self._has_message(res, ident):
            raise ELM327Error("Manually changed protocol '{:}' does not match currently active protocol '{:}'".format(ident, res))

        # Initialize protocol parser
        return self.supported_protocols()[ident](res_0100)


    def _auto_protocol(self, verify=True):
        """
        Attempts communication with the car.
        Upon success, the appropriate protocol parser is loaded.
        """

        # Set auto protocol mode
        res = self.send(b"ATSP0")
        if not self._is_ok(res):
            raise ELM327Error("Invalid response when setting auto protocol mode: {:}".format(res))

        # Search for protocol and verify connectivity
        res_0100 = self._verify_protocol("auto", force=not verify)

        # Get protocol number
        res = self.send(b"ATDPN")
        if len(res) != 1:
            logger.error("Invalid response when getting protocol number: {:}".format(res))
            raise ELM327Error("Failed to retrieve current protocol after searching for protocol automatically")

        ident = res[0]  # Grab the first (and only) line returned
        # Suppress any "automatic" prefix
        ident = ident[1:] if (len(ident) > 1 and ident.startswith("A")) else ident

        # Check if the protocol is supported
        if not ident in self.supported_protocols():
            raise ELM327Error("Automatically detected protocol '{:}' is not supported".format(ident))

        # Instantiate the corresponding protocol parser
        return self.supported_protocols()[ident](res_0100)


    def _trigger_status_callback(self, **kwargs):
        if self._status_callback:
            try:
                self._status_callback(self._status, **kwargs)
            except:
                logger.exception("Failed to trigger status callback")


    def _get_pps(self):
        """
        Retrieves all programmable parameters.
        """

        ret = {}

        lines = self.send(b"ATPPS")
        for line in lines:
            for param in line.split("  "):
                match = re.match("^(?P<id>[0-9A-F]{2}):(?P<value>[0-9A-F]{2}) (?P<state>[N|F]{1})$", param)
                if match:
                    group = match.groupdict()
                    ret[group["id"]] = group
                else:
                    raise ELM327Error("Unable to parse programmable parameter: {:}".format(param))

        return ret


    def _set_pp(self, id, value, enable=None):
        """
        Sets value of a programmable parameter and enables it if requested.
        """

        res = self.send(b"ATPP{:s} SV{:s}".format(id, value))
        if self._is_ok(res):
            logger.info("Updated programmable parameter '{:}' value '{:}'".format(id, value))
        else:
            raise ELM327Error("Failed to set programmable parameter '{:}' value '{:}': {:}".format(id, value, res))

        if enable is not None:
            res = self.send(b"ATPP{:s} {:s}".format(id, "ON" if enable else "OFF"))
            if self._is_ok(res):
                logger.info("{:} programmable parameter '{:}'".format("Enabled" if enable else "Disabled", id))
            else:
                raise ELM327Error("Failed to {:} programmable parameter '{:}': {:}".format("enable" if enable else "disable", id, res))


    def _ensure_pp(self, param, value, default=None):
        """
        Ensures a programmable parameter value is set if required.
        Returns True of False indicating if changes have been made.
        """

        # Check if default value and state is already fulfilled
        if default != None and default == value and default == param["value"] and param["state"] == "F":
            return False

        # Check if value is changed
        if value == param["value"] and param["state"] == "N":
            return False

        # Go ahead and update parameter
        if default != None and default == value:
            self._set_pp(param["id"], default, enable=False)
        else:
            self._set_pp(param["id"], value, enable=True)

        return True


    def _write(self, cmd):
        """
        Low-level function to write a string to the port.
        """

        if not self._port or not self._port.is_open:
            raise ELM327Error("Cannot write when serial connection is not open")

        cmd += b"\r\n"  # Terminate
        
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Write: " + repr(cmd))

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
            raise ELM327Error("Cannot read when serial connection is not open")

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
            if buffer.endswith(self.PROMPT):
                break

            # Check if it is time to send an interrupt character
            if interrupt_delay != None and (timer() - start) >= interrupt_delay:
                logger.info("Sending interrupt character during read")

                self._port.write(b"\x7F")
                interrupt_delay = None

        # Log, and remove the "bytearray(   ...   )" part
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Read: " + repr(buffer)[10:-1])

        # Clean out any null characters
        buffer = re.sub(b"\x00", b"", buffer)

        # Remove the prompt characters
        if buffer.endswith(self.PROMPT):
            buffer = buffer[:-len(self.PROMPT)]

        # Convert bytes into a standard string
        string = buffer.decode()

        # Splits into lines while removing empty lines and trailing spaces
        lines = [s.strip() for s in re.split("[\r\n]", string) if bool(s)]

        return lines


    def _is_ok(self, lines, expect_echo=False):
        if not lines:
            return False

        if not self._echo_off or expect_echo:
            return self._has_message(lines, self.OK) == self.OK

        return len(lines) == 1 and lines[0] == self.OK


    def _has_message(self, lines, *args):
        for line in lines:
            for arg in args:
                if arg in line:
                    return arg

        return None

