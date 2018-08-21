# -*- coding: utf-8 -*-

########################################################################
#                                                                      #
# python-OBD: A python OBD-II serial module derived from pyobd         #
#                                                                      #
# Copyright 2004 Donour Sizemore (donour@uchicago.edu)                 #
# Copyright 2009 Secons Ltd. (www.obdtester.com)                       #
# Copyright 2009 Peter J. Creath                                       #
# Copyright 2016 Brendan Whitfield (brendan-w.com)                     #
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

        After instantiation with a portname (/dev/ttyUSB0, etc...),
        the following functions become available:

            send()
            close()
            status()
            ecus()
    """

    ELM_PROMPT = b'\r>'

    _SUPPORTED_PROTOCOLS = {
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

    # used as a fallback, when ATSP0 doesn't cut it
    _TRY_PROTOCOL_ORDER = [
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
    _TRY_BAUDS = [9600, 576000, 230400, 115200, 57600, 38400, 19200]


    def __init__(self, portname, baudrate, protocol, is_echo=True):
        """
        Initializes port by resetting device and gettings supported PIDs.
        """

        logger.info("Initializing ELM327: PORT=%s BAUD=%s PROTOCOL=%s" %
                    (
                        portname,
                        "auto" if baudrate is None else baudrate,
                        "auto" if protocol is None else protocol,
                    ))

        self.__status   = OBDStatus.NOT_CONNECTED
        self.__port     = None
        self.__protocol = UnknownProtocol([])
        self.__is_echo  = is_echo

        # ------------- open port -------------
        try:
            self.__port = serial.Serial(portname,
                                        parity   = serial.PARITY_NONE,
                                        stopbits = 1,
                                        bytesize = 8,
                                        timeout  = 10) # seconds
        except serial.SerialException as e:
            self.__error(e)
            return
        except OSError as e:
            self.__error(e)
            return

        # ------------------------ find the ELM's baud ------------------------

        if not self.set_baudrate(baudrate):
            self.__error("Failed to set baudrate")
            return

        # ---------------------------- ATI (get ID) ---------------------------
        try:
            self.__send(b"ATI", delay=1) # wait 1 second for ELM to initialize
            # return data can be junk, so don't bother checking
        except serial.SerialException as e:
            self.__error(e)
            return

        # -------------------------- ATE1/ATE0 (echo ON/OFF) --------------------------
        r = self.__send(b"ATE{:d}".format(self.__is_echo))
        if not self.__is_ok(r, expect_echo=True):
            self.__error("ATE{:d} did not return 'OK'".format(self.__is_echo))
            return

        # ------------------------- ATH1 (headers ON) -------------------------
        r = self.__send(b"ATH1")
        if not self.__is_ok(r):
            self.__error("ATH1 did not return 'OK', or echoing is still ON")
            return

        # ------------------------ ATL0 (linefeeds OFF) -----------------------
        r = self.__send(b"ATL0")
        if not self.__is_ok(r):
            self.__error("ATL0 did not return 'OK'")
            return

        # by now, we've successfuly communicated with the ELM, but not the car
        self.__status = OBDStatus.ELM_CONNECTED

        # try to communicate with the car, and load the correct protocol parser
        if self.set_protocol(protocol):
            self.__status = OBDStatus.CAR_CONNECTED
            logger.info("Connected Successfully: PORT=%s BAUD=%s PROTOCOL=%s" %
                        (
                            portname,
                            self.__port.baudrate,
                            self.__protocol.ID,
                        ))
        else:
            logger.error("Connected to the adapter, but failed to connect to the vehicle")


    def supported_protocols(self):
        return self._SUPPORTED_PROTOCOLS


    def set_protocol(self, protocol):
        if protocol is not None:
            # an explicit protocol was specified
            if protocol not in self.supported_protocols():
                logger.error("%s is not a valid protocol", protocol)
                return False
            return self.manual_protocol(protocol)
        else:
            # auto detect the protocol
            return self.auto_protocol()


    def manual_protocol(self, protocol):
        r = self.__send(b"ATTP" + protocol.encode())
        if not self.__has_message(r, "OK"):
            logger.error("Got unexpected response when attempting to manually change to protocol ID '{:}': {:}".format(protocol, r))
            return False

        r = self.__send(b"ATDPN")
        if not self.__has_message(r, protocol):
            logger.error("Manually changed protocol ID '{:}' does not match currently active protocol ID '{:}'".format(protocol, r))
            return False

        r0100 = self.__send(b"0100")
        if not self.__has_message(r0100, "UNABLE TO CONNECT"):
            self.__protocol = self.supported_protocols()[protocol](r0100)
        else:
            logger.error("Unable to connect using protocol ID '{:}'".format(protocol))
            return False

        return True


    def auto_protocol(self):
        """
            Attempts communication with the car.

            If no protocol is specified, then protocols at tried with `ATTP`

            Upon success, the appropriate protocol parser is loaded,
            and this function returns True
        """

        # -------------- try the ELM's auto protocol mode --------------
        r = self.__send(b"ATSP0")

        # -------------- 0100 (first command, SEARCH protocols) --------------
        r0100 = self.__send(b"0100")

        # ------------------- ATDPN (list protocol number) -------------------
        r = self.__send(b"ATDPN")
        if len(r) != 1:
            logger.error("Failed to retrieve current protocol")
            return False


        p = r[0] # grab the first (and only) line returned
        # suppress any "automatic" prefix
        p = p[1:] if (len(p) > 1 and p.startswith("A")) else p

        # check if the protocol is something we know
        if p in self.supported_protocols():
            # jackpot, instantiate the corresponding protocol handler
            self.__protocol = self.supported_protocols()[p](r0100)
            return True
        else:
            # an unknown protocol
            # this is likely because not all adapter/car combinations work
            # in "auto" mode. Some respond to ATDPN responded with "0"
            logger.info("ELM responded with unknown protocol. Trying them one-by-one")

            for p in self._TRY_PROTOCOL_ORDER:
                r = self.__send(b"ATTP" + p.encode())
                r0100 = self.__send(b"0100")
                if not self.__has_message(r0100, "UNABLE TO CONNECT"):
                    # success, found the protocol
                    self.__protocol = self.supported_protocols()[p](r0100)
                    return True

        # if we've come this far, then we have failed...
        logger.error("Failed to determine protocol")
        return False


    def set_baudrate(self, baud):
        if baud is None:
            # when connecting to pseudo terminal, don't bother with auto baud
            if self.__port.portstr.startswith("/dev/pts"):
                logger.warning("Detected pseudo terminal, skipping baudrate setup")
                return True
            else:
                return self.auto_baudrate(self._TRY_BAUDS)
        elif isinstance(baud, list):
            return self.auto_baudrate(baud)
        else:

            # Create a list of choices with given baudrate as first entry
            choices = list(self._TRY_BAUDS)
            choices.remove(baud)
            choices.insert(0, baud)

            return self.auto_baudrate(choices)


    def auto_baudrate(self, choices):
        """
        Detect the baud rate at which a connected ELM32x interface is operating.
        Returns boolean for success.
        """

        # before we change the timout, save the "normal" value
        timeout = self.__port.timeout
        self.__port.timeout = 0.1 # we're only talking with the ELM, so things should go quickly

        for baud in choices:
            self.__port.baudrate = baud
            self.__port.flushInput()
            self.__port.flushOutput()

            # Send a nonsense command to get a prompt back from the scanner
            # (an empty command runs the risk of repeating a dangerous command)
            # The first character might get eaten if the interface was busy,
            # so write a second one (again so that the lone CR doesn't repeat
            # the previous command)
            self.__port.write(b"\x7F\x7F\r\n")
            self.__port.flush()
            response = self.__port.read(1024)
            logger.debug("Response from baud %d: %s" % (baud, repr(response)))

            # watch for the prompt character
            if response.endswith(b">"):
                logger.info("Choosing baudrate: %d" % baud)
                self.__port.timeout = timeout # reinstate our original timeout
                return True

        logger.error("Failed to choose baudrate")
        self.__port.timeout = timeout # reinstate our original timeout
        return False


    def __is_ok(self, lines, expect_echo=False):
        if not lines:
            return False
        if self.__is_echo or expect_echo:
            # don't test for the echo itself
            # allow the adapter to already have echo disabled
            return self.__has_message(lines, 'OK')
        else:
            return len(lines) == 1 and lines[0] == 'OK'


    def __has_message(self, lines, text):
        for line in lines:
            if text in line:
                return True
        return False


    def __error(self, msg):
        """ handles fatal failures, print logger.info info and closes serial """
        self.close()
        logger.error(str(msg))


    def connection_info(self):
        return {
            "port": self.__port.portstr,
            "baudrate": self.__port.baudrate
        } if self.__port else {}


    def status(self):
        return self.__status


    def ecus(self):
        return self.__protocol.ecu_map.values()


    def protocol(self):
        return self.__protocol


    def protocol_info(self):
        return {
            "id": self.__protocol.ID,
            "name": self.__protocol.NAME
        } if self.__protocol else {}


    def close(self):
        """
            Resets the device, and sets all
            attributes to unconnected states.
        """

        self.__status   = OBDStatus.NOT_CONNECTED
        self.__protocol = None

        if self.__port is not None:
            logger.info("Closing port")
            self.__port.close()
            self.__port = None


    def send(self, cmd, parse=True):
        """
            send() function used to service all OBDCommands

            Sends the given command string, and if requested
            parses the response lines with the protocol object.

            An empty command string will re-trigger the previous command

            Returns a list of parsed Message objects or raw response lines
        """

        if self.__status == OBDStatus.NOT_CONNECTED:
            logger.info("Cannot send when unconnected")
            return None

        lines = self.__send(cmd)

        if not parse:
            return lines

        messages = self.__protocol(lines)
        return messages


    def __send(self, cmd, delay=None):
        """
            unprotected send() function

            will __write() the given string, no questions asked.
            returns result of __read() (a list of line strings)
            after an optional delay.
        """

        self.__write(cmd)

        if delay is not None:
            logger.debug("Wait: %d seconds" % delay)
            time.sleep(delay)

        lines = self.__read()

        # get rid of echo if on
        if self.__is_echo and len(lines) > 1:

            # sanity check if echo matches sent command
            if cmd != lines[0]:
                logger.warning("Sent command does not match echo: '{:}' != '{:}'".format(cmd, lines[0]))

            lines = lines[1:]

        return lines


    def __write(self, cmd):
        """
            "low-level" function to write a string to the port
        """

        if self.__port:
            cmd += b"\r\n" # terminate
            logger.debug("write: " + repr(cmd))
            self.__port.flushInput() # dump everything in the input buffer
            self.__port.write(cmd) # turn the string into bytes and write
            self.__port.flush() # wait for the output buffer to finish transmitting
        else:
            logger.info("Cannot perform __write() when unconnected")


    def __read(self):
        """
            "low-level" read function

            accumulates characters until the prompt character is seen
            returns a list of [/r/n] delimited strings
        """
        if not self.__port:
            logger.info("Cannot perform __read() when unconnected")
            return []

        buffer = bytearray()

        while True:
            # retrieve as much data as possible
            data = self.__port.read(self.__port.in_waiting or 1)

            # if nothing was recieved
            if not data:
                logger.warning("Failed to read port")
                break

            buffer.extend(data)

            # end on chevron + carriage return (ELM prompt characters)
            if buffer.endswith(self.ELM_PROMPT):
                break

        # log, and remove the "bytearray(   ...   )" part
        logger.debug("read: " + repr(buffer)[10:-1])

        # clean out any null characters
        buffer = re.sub(b"\x00", b"", buffer)

        # remove the prompt characters
        if buffer.endswith(self.ELM_PROMPT):
            buffer = buffer[:-len(self.ELM_PROMPT)]

        # convert bytes into a standard string
        string = buffer.decode()

        # splits into lines while removing empty lines and trailing spaces
        lines = [ s.strip() for s in re.split("[\r\n]", string) if bool(s) ]

        return lines
