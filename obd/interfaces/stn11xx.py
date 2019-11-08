import datetime
import collections
import logging

from timeit import default_timer as timer
from .elm327 import ELM327, ELM327Error
from ..protocols import *
from ..utils import OBDStatus


logger = logging.getLogger(__name__)


########################################################################
# Protocol definitions
########################################################################

# J1850

class J1850_PWM(LegacyProtocol):
    NAME = "J1850 PWM"
    ID = "11"
    def __init__(self, lines_0100):
        LegacyProtocol.__init__(self, lines_0100)

class J1850_VPW(LegacyProtocol):
    NAME = "J1850 VPW"
    ID = "12"
    def __init__(self, lines_0100):
        LegacyProtocol.__init__(self, lines_0100)

# ISO

class ISO_9141(LegacyProtocol):
    NAME = "ISO 9141 (no header, no autoinit)"
    ID = "21"
    def __init__(self, lines_0100):
        LegacyProtocol.__init__(self, lines_0100)

class ISO_9141_2(LegacyProtocol):
    NAME = "ISO 9141-2 (5 baud autoinit)"
    ID = "22"
    def __init__(self, lines_0100):
        LegacyProtocol.__init__(self, lines_0100)

class ISO_14230(LegacyProtocol):
    NAME = "ISO 14230 (no autoinit)"
    ID = "23"
    def __init__(self, lines_0100):
        LegacyProtocol.__init__(self, lines_0100)

class ISO_14230_5baud(LegacyProtocol):
    NAME = "ISO 14230 (5 baud autoinit)"
    ID = "24"
    def __init__(self, lines_0100):
        LegacyProtocol.__init__(self, lines_0100)

class ISO_14230_fast(LegacyProtocol):
    NAME = "ISO 14230 (fast autoinit)"
    ID = "25"
    def __init__(self, lines_0100):
        LegacyProtocol.__init__(self, lines_0100)

# High Speed CAN

class HSC_ISO_11898_11bit_500k(CANProtocol):
    NAME = "HS CAN (ISO 11898, 11bit, 500kbps, var DLC)"
    ID = "31"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=11)

class HSC_ISO_11898_29bit_500k(CANProtocol):
    NAME = "HS CAN (ISO 11898, 29bit, 500kbps, var DLC)"
    ID = "32"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=29)

class HSC_ISO_15765_11bit_500k(CANProtocol):
    NAME = "HS CAN (ISO 15765, 11bit, 500kbps, DLC=8)"
    ID = "33"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=11)

class HSC_ISO_15765_29bit_500k(CANProtocol):
    NAME = "HS CAN (ISO 15765, 29bit, 500kbps, DLC=8)"
    ID = "34"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=29)

class HSC_ISO_15765_11bit_250k(CANProtocol):
    NAME = "HS CAN (ISO 15765, 11bit, 250kbps, DLC=8)"
    ID = "35"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=11)

class HSC_ISO_15765_29bit_250k(CANProtocol):
    NAME = "HS CAN (ISO 15765, 29bit, 250kbps, DLC=8)"
    ID = "36"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=29)

class HSC_J1939_11bit_250k(CANProtocol):
    NAME = "J1939 (11bit, 250kbps)"
    ID = "41"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=11)

class HSC_J1939_29bit_250k(CANProtocol):
    NAME = "J1939 (29bit, 250kbps)"
    ID = "42"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=29)

# Medium Speed CAN

class MSC_ISO_11898_11bit_125k(CANProtocol):
    NAME = "MS CAN (ISO 11898, 11bit, 125kbps, var DLC)"
    ID = "51"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=11)

class MSC_ISO_11898_29bit_125k(CANProtocol):
    NAME = "MS CAN (ISO 11898, 29bit, 125kbps, var DLC)"
    ID = "52"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=29)

class MSC_ISO_15765_11bit_125k(CANProtocol):
    NAME = "MS CAN (ISO 15765, 11bit, 125kbps, DLC=8)"
    ID = "53"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=11)

class MSC_ISO_15765_29bit_125k(CANProtocol):
    NAME = "MS CAN (ISO 15765, 29bit, 125kbps, DLC=8)"
    ID = "54"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=29)

# Single Wire CAN

class SWC_ISO_11898_11bit_33k3(CANProtocol):
    NAME = "SW CAN (ISO 11898, 11bit, 33.3kbps, var DLC)"
    ID = "61"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=11)

class SWC_ISO_11898_29bit_33k3(CANProtocol):
    NAME = "SW CAN (ISO 11898, 29bit, 33.3kbps, var DLC)"
    ID = "62"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=29)

class SWC_ISO_15765_11bit_33k3(CANProtocol):
    NAME = "SW CAN (ISO 15765, 11bit, 33.3kbps, DLC=8)"
    ID = "63"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=11)

class SWC_ISO_15765_29bit_33k3(CANProtocol):
    NAME = "SW CAN (ISO 15765, 29bit, 33.3kbps, DLC=8)"
    ID = "64"
    def __init__(self, lines_0100):
        CANProtocol.__init__(self, lines_0100, id_bits=29)


########################################################################
# Interface implementation
########################################################################

class STN11XXError(ELM327Error):

    def __init__(self, *args, **kwargs):
        super(STN11XXError, self).__init__(*args, **kwargs)

class STN11XX(ELM327):
    """
        Handles communication with the STN11XX adapter.

        See: https://www.scantool.net/scantool/downloads/234/stn1100-frpm-preliminary.pdf
    """

    STN_SUPPORTED_PROTOCOLS = collections.OrderedDict({

        # J1850
        J1850_PWM.ID:                 J1850_PWM,                 # J1850 PWM
        J1850_VPW.ID:                 J1850_VPW,                 # J1850 VPW

        # ISO
        ISO_9141.ID:                  ISO_9141,                  # ISO 9141 (no header, no autoinit)
        ISO_9141_2.ID:                ISO_9141_2,                # ISO 9141-2 (5 baud autoinit)
        ISO_14230.ID:                 ISO_14230,                 # ISO 14230 (no autoinit)
        ISO_14230_5baud.ID:           ISO_14230_5baud,           # ISO 14230 (5 baud autoinit)
        ISO_14230_fast.ID:            ISO_14230_fast,            # ISO 14230 (fast autoinit)

        # High Speed CAN
        HSC_ISO_11898_11bit_500k.ID:  HSC_ISO_11898_11bit_500k,  # HS CAN (ISO 11898, 11bit, 500kbps, var DLC)
        HSC_ISO_11898_29bit_500k.ID:  HSC_ISO_11898_29bit_500k,  # HS CAN (ISO 11898, 29bit, 500kbps, var DLC)
        HSC_ISO_15765_11bit_500k.ID:  HSC_ISO_15765_11bit_500k,  # HS CAN (ISO 15765, 11bit, 500kbps, DLC=8)
        HSC_ISO_15765_29bit_500k.ID:  HSC_ISO_15765_29bit_500k,  # HS CAN (ISO 15765, 29bit, 500kbps, DLC=8)
        HSC_ISO_15765_11bit_250k.ID:  HSC_ISO_15765_11bit_250k,  # HS CAN (ISO 15765, 11bit, 250kbps, DLC=8)
        HSC_ISO_15765_29bit_250k.ID:  HSC_ISO_15765_29bit_250k,  # HS CAN (ISO 15765, 29bit, 250kbps, DLC=8)

        HSC_J1939_11bit_250k.ID:      HSC_J1939_11bit_250k,      # J1939 (11bit, 250kbps)
        HSC_J1939_29bit_250k.ID:      HSC_J1939_29bit_250k,      # J1939 (29bit, 250kbps)

        # Medium Speed CAN
        MSC_ISO_11898_11bit_125k.ID:  MSC_ISO_11898_11bit_125k,  # MS CAN (ISO 11898, 11bit, 125kbps, var DLC)
        MSC_ISO_11898_29bit_125k.ID:  MSC_ISO_11898_29bit_125k,  # MS CAN (ISO 11898, 29bit, 125kbps, var DLC)
        MSC_ISO_15765_11bit_125k.ID:  MSC_ISO_15765_11bit_125k,  # MS CAN (ISO 15765, 11bit, 125kbps, DLC=8)
        MSC_ISO_15765_29bit_125k.ID:  MSC_ISO_15765_29bit_125k,  # MS CAN (ISO 15765, 29bit, 125kbps, DLC=8)

        # Single Wire CAN
        SWC_ISO_11898_11bit_33k3.ID:  SWC_ISO_11898_11bit_33k3,   # SW CAN (ISO 11898, 11bit, 33.3kbps, var DLC)
        SWC_ISO_11898_29bit_33k3.ID:  SWC_ISO_11898_29bit_33k3,   # SW CAN (ISO 11898, 29bit, 33.3kbps, var DLC)
        SWC_ISO_15765_11bit_33k3.ID:  SWC_ISO_15765_11bit_33k3,   # SW CAN (ISO 15765, 11bit, 33.3kbps, DLC=8)
        SWC_ISO_15765_29bit_33k3.ID:  SWC_ISO_15765_29bit_33k3,   # SW CAN (ISO 15765, 29bit, 33.3kbps, DLC=8)
    })

    # We check the the default baud rate first, then go fastest to
    # slowest, on the theory that anyone who's using a slow baud rate is
    # going to be less picky about the time required to detect it.
    TRY_BAUDRATES = [9600, 2304000, 1152000, 1056000, 960000, 576000, 230400, 115200, 57600, 38400, 19200]

    FILTER_TYPE_PASS = "PASS"
    FILTER_TYPE_BLOCK = "BLOCK"
    FILTER_TYPE_FLOW = "FLOW"
    FILTER_TYPES = [FILTER_TYPE_PASS, FILTER_TYPE_BLOCK, FILTER_TYPE_FLOW]


    def __init__(self, *args, **kwargs):
        super(STN11XX, self).__init__(*args, **kwargs)

        self._filters = []


    def set_baudrate(self, baudrate):

        # Set baudrate as usual if not already connected
        if self._status == OBDStatus.NOT_CONNECTED:
            super(STN11XX, self).set_baudrate(baudrate)

            return

        # Skip if baudrate is already set
        if baudrate == self._port.baudrate:
            return

        # Tell STN1XX to switch to new baudrate
        self._write("STSBR" + str(baudrate))
        logger.info("Changed baudrate of serial connection from '{:}' to '{:}'".format(self._port.baudrate, baudrate))

        super(STN11XX, self).set_baudrate(baudrate)


    def supported_protocols(self):
        ret = collections.OrderedDict()
        ret.update(self.SUPPORTED_PROTOCOLS)
        ret.update(self.STN_SUPPORTED_PROTOCOLS)

        return ret


    def set_protocol(self, ident, **kwargs):

        ret = super(STN11XX, self).set_protocol(ident, **kwargs)

        # Always determine current protocol baudrate
        res = self.send("STPBRR")
        self._protocol.baudrate = int(next(iter(res), "0"))

        # Check if STN baudrate is lower than protocol baudrate
        if self._protocol.baudrate > self._port.baudrate:

            # Find first sufficient baudrate
            for try_baudrate in sorted(self.TRY_BAUDRATES):
                if try_baudrate >= self._protocol.baudrate:

                    # Use faster baudrate
                    self.set_baudrate(try_baudrate)

                    return ret

            logger.warning("Serial connection baudrate '{:}' is lower than protocol baudrate '{:}'".format(self._port.baudrate, self._protocol.baudrate))

        # Check that specified baudrate is set
        if kwargs.get("baudrate", None) != None and kwargs["baudrate"] != self._protocol.baudrate:
            raise STN11XXError("Requested baudrate could not be set - be aware that ELM327 protocols does not support custom baudrates")

        return ret


    def set_can_monitor_mode(self, value):
        """
        Set CAN monitoring mode. Default is 0.

        Mode options:
            0 = Receive only - no CAN ACKs (default).
            1 = Normal node - with CAN ACKs.
            2 = Receive all frames, including frames with errors - no CAN ACKs.
        """

        if value == self._runtime_settings.get("can_monitor_mode", 0):
            return

        try:
            res = self.send("STCMM" + str(value))
        except ELM327Error as err:
            raise STN11XXError("Unable to set CAN monitoring mode '{:}': {:}".format(value, err))

        if not self._is_ok(res):
            raise STN11XXError("Invalid response when setting CAN monitoring mode '{:}': {:}".format(value, res))

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Changed CAN monitoring mode from '{:}' to '{:}'".format(self._runtime_settings.get("can_monitor_mode", None), value))

        self._runtime_settings["can_monitor_mode"] = value


    def monitor(self, duration=10, mode=0, auto_format=False, filtering=False):
        """
        Monitor messages on bus. For CAN protocols, all messages will be treated as ISO 15765.
        """

        # Ensure CAN automatic formatting
        self.set_can_auto_format(auto_format)

        # Ensure CAN monitoring mode
        self.set_can_monitor_mode(mode)

        timeout = self._port.timeout
        try:
            if duration == None:

                # Ensure monitor state
                if filtering and self._state != self.STATE_MONITOR:
                    self._write("STM")

                    # Change state of interface
                    self._state = self.STATE_MONITOR
                elif not filtering and self._state != self.STATE_MONITOR_ALL:
                    self._write("STMA")

                    # Change state of interface
                    self._state = self.STATE_MONITOR_ALL

            else:
                self._port.timeout = duration

                return self.send("STM" if filtering else "STMA", interrupt_delay=duration)
        finally:
            if self._port.timeout != timeout:
                self._port.timeout = timeout


    def monitor_continuously(self, wait=False, limit=None, duration=None, enrich=None, **kwargs):
        """
        Monitor messages on bus continuously.
        """

        ret = []

        # Ensure infinite monitoring
        self.monitor(duration=None, **kwargs)

        # Read lines until last or limit reached
        start = timer()
        count = 0
        while True:
            count += 1

            res = self._read_line(wait=wait or count==1)  # Always wait for the first line

            # Return what we got so far if no more lines to read
            if res == None:
                break

            # Enrich result if requested
            if enrich:
                res = enrich(res)

            ret.append(res)

            # Check if limit has been reached
            if limit and count >= limit:
                if wait:
                    logger.info("Read limit of {:} line(s) reached".format(limit))
                else:
                    logger.warning("Read limit of {:} line(s) reached - this may indicate that more data is being produced than can be handled".format(limit))

                break

            # Check if duration has been reached
            if duration and (timer() - start) >= duration:
                logger.info("Duration of {:} second(s) reached - read {:} line(s)".format(duration, count))

                break

        return ret


    def list_filters(self, type=None):
        # TODO HN: Rewrite to use self._runtime_settings

        if type != None:
            type = type.upper()

        if type and type not in self.FILTER_TYPES:
            raise ValueError("Unsupported filter type - allowed options are: {:}".format(", ".join(self.FILTER_TYPES)))

        return [f.copy() for f in self._filters if type == None or f["type"] == type]


    def add_filter(self, type, pattern, mask):
        # TODO HN: Rewrite to use self._runtime_settings

        if type != None:
            type = type.upper()

        cmd = None
        if type == self.FILTER_TYPE_PASS:
            cmd = "STFAP"
        elif type == self.FILTER_TYPE_BLOCK:
            cmd = "STFAB"
        elif type == self.FILTER_TYPE_FLOW:
            cmd = "STFAFC"
        else:
            raise ValueError("Unsupported filter type - allowed options are: {:}".format(", ".join(self.FILTER_TYPES)))

        res = self.send("{:} {:},{:}".format(cmd, pattern, mask))
        if not self._is_ok(res):
            raise STN11XXError("Failed to add '{:}' filter: {:}".format(type, res))

        self._filters.append({
                "type": type,
                "pattern": pattern,
                "mask": mask
            })


    def clear_filters(self, type=None):
        # TODO HN: Rewrite to use self._runtime_settings

        if type != None:
            type = type.upper()

        if type and type not in self.FILTER_TYPES:
            raise ValueError("Unsupported filter type - allowed options are: {:}".format(", ".join(self.FILTER_TYPES)))

        if type == None or type == self.FILTER_TYPE_PASS:
            res = self.send("STFCP")
            if not self._is_ok(res):
                raise STN11XXError("Failed to clear '{:}' filters: {:}".format(self.FILTER_TYPE_PASS, res))

            self._filters = list(filter(lambda f: f["type"] != self.FILTER_TYPE_PASS, self._filters))

        if type == None or type == self.FILTER_TYPE_BLOCK:
            res = self.send("STFCB")
            if not self._is_ok(res):
                raise STN11XXError("Failed to clear '{:}' filters: {:}".format(self.FILTER_TYPE_BLOCK, res))

            self._filters = list(filter(lambda f: f["type"] != self.FILTER_TYPE_BLOCK, self._filters))

        if type == None or type == self.FILTER_TYPE_FLOW:
            res = self.send("STFCFC")
            if not self._is_ok(res):
                raise STN11XXError("Failed to clear '{:}' filters: {:}".format(self.FILTER_TYPE_FLOW, res))

            self._filters = list(filter(lambda f: f["type"] != self.FILTER_TYPE_FLOW, self._filters))


    def can_flow_control_filters(self, clear=False, add=None):

        if clear:

            try:
                res = self.send("STFFCC")
            except ELM327Error as err:
                raise STN11XXError("Unable to clear CAN flow control filters: {:}".format(err))

            if not self._is_ok(res):
                raise STN11XXError("Invalid response when clearing CAN flow control filters: {:}".format(res))

            self._runtime_settings["can_flow_control_filters"] = []

        if add:
            add = str(add).replace(" ", "").upper()
            if not add in self._runtime_settings.get("can_flow_control_filters", []):

                try:                
                    res = self.send("STFFCA{:}".format(add))
                except ELM327Error as err:
                    raise STN11XXError("Unable to add CAN flow control filter '{:}': {:}".format(add, err))

                if not self._is_ok(res):
                    raise STN11XXError("Invalid response when adding CAN flow control filter '{:}': {:}".format(add, res))

                self._runtime_settings.setdefault("can_flow_control_filters", []).append(add)

        return self._runtime_settings.get("can_flow_control_filters", [])


    def can_flow_control_id_pairs(self, clear=False, add=None):

        if clear:

            try:
                res = self.send("STCFCPC")
            except ELM327Error as err:
                raise STN11XXError("Unable to clear CAN flow control ID pairs: {:}".format(err))

            if not self._is_ok(res):
                raise STN11XXError("Invalid response when clearing CAN flow control ID pairs: {:}".format(res))

            self._runtime_settings["can_flow_control_id_pairs"] = []

        if add:
            add = str(add).replace(" ", "").upper()
            if not add in self._runtime_settings.get("can_flow_control_id_pairs", []):

                try:
                    res = self.send("STCFCPA{:}".format(add))
                except ELM327Error as err:
                    raise STN11XXError("Unable to add CAN flow control ID pair '{:}': {:}".format(add, err))

                if not self._is_ok(res):
                    raise STN11XXError("Invalid response when adding CAN flow control ID pair '{:}': {:}".format(add, res))

                self._runtime_settings.setdefault("can_flow_control_id_pairs", []).append(add)

        return self._runtime_settings.get("can_flow_control_id_pairs", [])


    def _manual_protocol(self, ident, verify=False, baudrate=None):

        # Call super method if not a STN protocol
        if not ident in self.STN_SUPPORTED_PROTOCOLS:
            return super(STN11XX, self)._manual_protocol(ident, verify=verify)

        # Change protocol
        res = self.send("STP" + ident)
        if not self._is_ok(res):
            raise STN11XXError("Invalid response when manually changing to protocol '{:}': {:}".format(ident, res))

        # Verify protocol changed
        res = self.send("STPR")
        if not self._has_message(res, ident):
            raise STN11XXError("Manually changed protocol '{:}' does not match currently active protocol '{:}'".format(ident, res))

        # Also set protocol baudrate if specified
        if baudrate != None:
            res = self.send("STPBR" + str(baudrate))
            if not self._is_ok(res,):
                raise STN11XXError("Invalid response when setting baudrate '{:}' for protocol '{:}': {:}".format(baudrate, ident, res))

        # Verify if the protocol has OBD-II support
        if verify:
            res_0100 = self._verify_protocol(ident, test=not verify)

            # Initialize protocol parser
            return self.supported_protocols()[ident](res_0100)

        # Initialize protocol parser
        return self.supported_protocols()[ident]([])

