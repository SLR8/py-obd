import logging

from .elm327 import ELM327
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

class STN11XX(ELM327):
    """
        Handles communication with the STN11XX adapter.

        See: https://www.scantool.net/scantool/downloads/234/stn1100-frpm-preliminary.pdf
    """

    STN_SUPPORTED_PROTOCOLS = {

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
    }

    # We check the the default baud rate first, then go fastest to
    # slowest, on the theory that anyone who's using a slow baud rate is
    # going to be less picky about the time required to detect it.
    TRY_BAUDRATES = [9600, 2304000, 1152000, 576000, 230400, 115200, 57600, 38400, 19200]


    def __init__(self, *args, **kwargs):
        self._protocol_baudrate = None

        super(STN11XX, self).__init__(*args, **kwargs)


    def set_baudrate(self, baudrate):

        # Set baudrate as usual if not already connected
        if self._status == OBDStatus.NOT_CONNECTED:
            super(STN11XX, self).set_baudrate(baudrate)

            return

        # Skip if baudrate is already set
        if baudrate == self._port.baudrate:
            return

        # Tell STN1XX to switch to new baudrate
        self._write(b"STSBR" + str(baudrate).encode())
        logger.info("Changed serial connection baudrate from '{:}' to '{:}'".format(self._port.baudrate, baudrate))

        super(STN11XX, self).set_baudrate(baudrate)


    def supported_protocols(self):
        ret = {}
        ret.update(self.SUPPORTED_PROTOCOLS)
        ret.update(self.STN_SUPPORTED_PROTOCOLS)

        return ret


    def set_protocol(self, protocol, baudrate=None):
        ret = super(STN11XX, self).set_protocol(protocol)

        # TODO HN: Must be set before protocol is opened for the first time (before sending '0100')
        # Also set protocol baudrate if specified
        if baudrate != None:
            res = self.send(b"STPBR" + str(baudrate).encode())
            if not self._is_ok(res,):
                raise Exception("Invalid response when setting baudrate '{:}' for protocol '{:}': {:}".format(baudrate, protocol, res))

        # Always determine current protocol baudrate
        res = self.send(b"STPBRR")
        self._protocol_baudrate = next(iter(res), None)

        return ret


    def protocol_info(self):
        ret = super(STN11XX, self).protocol_info()
        if self._protocol_baudrate != None:
            ret["baudrate"] = int(self._protocol_baudrate)

        return ret


    def set_can_monitor_mode(self, value):
        """
        Set CAN monitoring mode.

        Mode options:
            0 = Receive only - no CAN ACKs (default)
            1 = Normal node - with CAN ACKs
            2 = Receive all frames, including frames with errors - no CAN ACKs
        """

        if value == self._can_monitor_mode:
            return

        res = self.send(b"STCMM" + str(mode).encode())
        if not self._is_ok(res):
            raise Exception("Invalid response when setting CAN monitoring mode '{:}': {:}".format(value, res))

        logger.info("Changed CAN monitoring mode from '{:}' to '{:}'".format(self._can_monitor_mode, value))
        self._can_monitor_mode = value


    def monitor_all(self, duration=10, mode=0, auto_format=True):
        """
        Monitor all messages on OBD bus. For CAN protocols, all messages will be treated as ISO 15765.
        """

        # Set CAN monitoring mode
        self.set_can_monitor_mode(mode)

        # Set CAN automatic formatting
        self.set_can_auto_format(auto_format)

        timeout = self._port.timeout
        self._port.timeout = duration

        try:
            return self.send(b"STMA", interrupt_delay=duration)
        finally:
            self._port.timeout = timeout


    def _manual_protocol(self, protocol):

        # Call super method if not a STN protocol
        if not protocol in self.STN_SUPPORTED_PROTOCOLS:
            return super(STN11XX, self)._manual_protocol(protocol)

        # Change protocol
        res = self.send(b"STP" + protocol.encode())
        if not self._is_ok(res):
            raise Exception("Invalid response when manually changing to protocol '{:}': {:}".format(protocol, res))

        # Verify protocol changed
        res = self.send(b"STPR")
        if not self._has_message(res, protocol):
            raise Exception("Manually changed protocol '{:}' does not match currently active protocol '{:}'".format(protocol, res))

        # Initialize protocol parser
        self._protocol = self.supported_protocols()[protocol]([])
        logger.info("Protocol '{:}' set manually: {:}".format(protocol, self._protocol))
