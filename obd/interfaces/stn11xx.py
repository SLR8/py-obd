import logging

from .elm327 import ELM327
from ..protocols import *


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
    """

    _STN_SUPPORTED_PROTOCOLS = {

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

    def __init__(self, *args, **kwargs):
        self.__protocol_baudrate = None

        super(STN11XX, self).__init__(*args, **kwargs)

    def supported_protocols(self):
        ret = {}
        ret.update(self._SUPPORTED_PROTOCOLS)
        ret.update(self._STN_SUPPORTED_PROTOCOLS)

        return ret

    def set_protocol(self, protocol, baudrate=None):
        ret = super(STN11XX, self).set_protocol(protocol)

        # Set protocol baudrate if specified
        if baudrate != None:
            r = self._ELM327__send(b"STPBR" + str(baudrate).encode())
            if not self._ELM327__has_message(r, "OK"):
                logger.error("Got unexpected response when setting baudrate '{:}' for protocol ID '{:}': {:}".format(baudrate, protocol, r))
                return False

        # Determine protocol baudrate
        r = self._ELM327__send(b"STPBRR")
        self.__protocol_baudrate = next(iter(r), None)

        return ret

    def manual_protocol(self, protocol):

        # Call super method if not a STN protocol
        if not protocol in self._STN_SUPPORTED_PROTOCOLS:
            return super(STN11XX, self).manual_protocol(protocol)

        # Change protocol
        r = self._ELM327__send(b"STP" + protocol.encode())
        if not self._ELM327__has_message(r, "OK"):
            logger.error("Got unexpected response when attempting to manually change to protocol ID '{:}': {:}".format(protocol, r))
            return False

        # Verify protocol is changed
        r = self._ELM327__send(b"STPR")
        if not self._ELM327__has_message(r, protocol):
            logger.error("Manually changed protocol ID '{:}' does not match currently active protocol ID '{:}'".format(protocol, r))
            return False

        # Verify connection
        r0100 = self._ELM327__send(b"0100")
        if not self._ELM327__has_message(r0100, "UNABLE TO CONNECT"):
            self._ELM327__protocol = self.supported_protocols()[protocol](r0100)
        else:
            logger.error("Unable to connect using protocol ID '{:}'".format(protocol))
            return False

        return True

    def protocol_info(self):
        ret = super(STN11XX, self).protocol_info()
        ret["baudrate"] = self.__protocol_baudrate

        return ret
