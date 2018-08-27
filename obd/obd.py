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
# obd.py                                                               #
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


import logging

from .__version__ import __version__
from .interfaces import *
from .commands import commands
from .OBDResponse import OBDResponse
from .utils import scan_serial, OBDStatus


logger = logging.getLogger(__name__)


class OBD(object):
    """
        Class representing an OBD-II connection
        with it's assorted commands/sensors.
    """

    def __init__(self, portstr=None, baudrate=None, protocol=None, fast=True, interface_cls=ELM327):
        self.interface = None
        self.supported_commands = set(commands.base_commands())
        self.fast = fast # global switch for disabling optimizations
        self.__last_command = b"" # used for running the previous command with a CR
        self.__frame_counts = {} # keeps track of the number of return frames for each command

        logger.debug("======================= python-OBD (v%s) =======================" % __version__)
        self.__connect(interface_cls, portstr, baudrate, protocol) # initialize by connecting and loading sensors
        self.__load_commands()            # try to load the car's supported commands
        logger.debug("===================================================================")


    def __connect(self, interface_cls, portstr, baudrate, protocol):
        """
            Attempts to instantiate and open an ELM327 interface connection object.
        """

        self.interface = interface_cls()

        if portstr is None:
            logger.info("Using serial scan to select port")

            portnames = scan_serial()
            if not portnames:
                logger.warning("No OBD-II adapters found")
                return

            logger.info("Available ports: " + str(portnames))

            for port in portnames:
                logger.info("Attempting to use port '{:}' ".format(port))

                try:
                    self.interface.open(port, baudrate, protocol)
                    if self.interface.status() >= OBDStatus.ELM_CONNECTED:
                        break # success! stop searching for serial

                except:
                    logger.exception("Failed to use port '{:}'".format(port))

        else:
            logger.debug("Explicit port defined")

            try:
                self.interface.open(portstr, baudrate, protocol)
            except:
                logger.exception("Failed to use explicit port '{:}'".format(portstr))

        if self.interface.status() == OBDStatus.NOT_CONNECTED:
            raise Exception("Failed to connect to interface '{:}' - see log for details".format(interface_cls))


    def __load_commands(self):
        """
            Queries for available PIDs, sets their support status,
            and compiles a list of command objects.
        """

        if self.status() != OBDStatus.CAR_CONNECTED:
            logger.warning("Cannot load commands: No connection to car")
            return

        logger.info("querying for supported commands")
        pid_getters = commands.pid_getters()
        for get in pid_getters:
            # PID listing commands should sequentialy become supported
            # Mode 1 PID 0 is assumed to always be supported
            if not self.test_cmd(get, warn=False):
                continue

            # when querying, only use the blocking OBD.query()
            # prevents problems when query is redefined in a subclass (like Async)
            response = OBD.query(self, get)

            if response.is_null():
                logger.info("No valid data for PID listing command: %s" % get)
                continue

            # loop through PIDs bitarray
            for i, bit in enumerate(response.value):
                if bit:

                    mode = get.mode
                    pid  = get.pid + i + 1

                    if commands.has_pid(mode, pid):
                        self.supported_commands.add(commands[mode][pid])

                    # set support for mode 2 commands
                    if mode == 1 and commands.has_pid(2, pid):
                        self.supported_commands.add(commands[2][pid])

        logger.info("Finished querying with %d commands supported" % len(self.supported_commands))


    def close(self):
        """
            Closes the connection, and clears supported_commands
        """

        self.supported_commands = set()

        if self.interface is not None:
            logger.info("Closing connection")
            self.interface.close()
            self.interface = None


    def status(self):
        """ returns the OBD connection status """
        if self.interface is None:
            return OBDStatus.NOT_CONNECTED
        else:
            return self.interface.status()


    # not sure how useful this would be

    # def ecus(self):
    #     """ returns a list of ECUs in the vehicle """
    #     if self.interface is None:
    #         return []
    #     else:
    #         return self.interface.ecus()


    def connection_info(self):
        """ Returns info of the serial connection  """
        if self.interface is None:
            return {}
        else:
            return self.interface.connection_info()


    def protocol_info(self):
        """ Returns the ID and name of the protocol being used by the interface """
        if self.interface is None:
            return {}
        else:
            return self.interface.protocol_info()


    def supported_protocols(self):
        """ Returns all protocols supported by the interface """
        if self.interface is None:
            return {}
        else:
            return self.interface.supported_protocols()


    def change_protocol(self, protocol, baudrate=None, reload_commands=True):
        """ Change protocol for interface """

        if self.status() == OBDStatus.NOT_CONNECTED:
            raise Exception("Not connected")

        ret = self.interface.set_protocol(protocol, baudrate=baudrate)

        if reload_commands:
            self.__load_commands()

        return ret


    def is_connected(self):
        """
            Returns a boolean for whether a connection with the car was made.

            Note: this function returns False when:
            obd.status = OBDStatus.ELM_CONNECTED
        """
        return self.status() == OBDStatus.CAR_CONNECTED


    def print_commands(self):
        """
            Utility function meant for working in interactive mode.
            Prints all commands supported by the car.
        """
        for c in self.supported_commands:
            print(str(c))


    def supports(self, cmd):
        """
            Returns a boolean for whether the given command
            is supported by the car
        """
        return cmd in self.supported_commands


    def test_cmd(self, cmd, warn=True):
        """
            Returns a boolean for whether a command will
            be sent without using force=True.
        """
        # test if the command is supported
        if not self.supports(cmd):
            if warn:
                logger.warning("'%s' is not supported" % str(cmd))
            return False

        # mode 06 is only implemented for the CAN protocols
        if cmd.mode == 6 and self.interface.protocol().ID not in ["6", "7", "8", "9"]:
            if warn:
                logger.warning("Mode 06 commands are only supported over CAN protocols")
            return False

        return True


    def query(self, cmd, force=False):
        """
            primary API function. Sends commands to the car, and
            protects against sending unsupported commands.
        """

        if self.status() == OBDStatus.NOT_CONNECTED:
            logger.warning("Query failed, no connection available")
            return OBDResponse()

        # if the user forces, skip all checks
        if not force and not self.test_cmd(cmd):
            return OBDResponse()

        # query command and retrieve message
        logger.debug("Querying command: %s" % str(cmd))
        cmd_string = self.__build_command_string(cmd)
        messages = self.interface.query(cmd_string, parse=True)

        # if we're sending a new command, note it
        # first check that the current command WASN'T sent as an empty CR
        # (CR is added by the ELM327 class)
        if cmd_string:
            self.__last_command = cmd_string

        # if we don't already know how many frames this command returns,
        # log it, so we can specify it next time
        if cmd not in self.__frame_counts:
            self.__frame_counts[cmd] = sum([len(m.frames) for m in messages])

        if not messages:
            logger.warning("No valid OBD Messages returned")
            return OBDResponse()

        return cmd(messages) # compute a response object


    def send(self, cmd_string, header=None, auto_format=True):
        """
            Low-level send/execute function.
        """

        if self.status() == OBDStatus.NOT_CONNECTED:
            raise Exception("Not connected")

        # Set given header or use default
        self.interface.set_header(ELM327.OBD_HEADER if header == None else header)

        # Set CAN automatic formatting
        self.interface.set_can_auto_format(auto_format)

        logger.debug("Sending: %s" % str(cmd_string))
        lines = self.interface.send(cmd_string)

        return lines


    def __build_command_string(self, cmd):
        """ assembles the appropriate command string """
        cmd_string = cmd.command

        # if we know the number of frames that this command returns,
        # only wait for exactly that number. This avoids some harsh
        # timeouts from the ELM, thus speeding up queries.
        if self.fast and cmd.fast and (cmd in self.__frame_counts):
            cmd_string += str(self.__frame_counts[cmd]).encode()

        # if we sent this last time, just send a CR
        # (CR is added by the ELM327 class)
        if self.fast and (cmd_string == self.__last_command):
            cmd_string = b""

        return cmd_string
