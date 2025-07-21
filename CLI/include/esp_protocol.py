from enum import Enum, auto
import serial #Documentation: https://pyserial.readthedocs.io/en/latest/index.html 
import time
from fingerprint_data import *

# --- Serial Communication ---
DEFAULT_SERIAL_PORT = '/dev/cu.usbserial-110'
DEFAULT_BAUD_RATE = 115200
DEFAULT_TIMEOUT = None

class CMD(Enum):
    SNIFF = 0
    DEAUTH = auto()
    PING = auto()
    INFO = auto()
    ACK = auto()
    ERR = auto()

class ARG(Enum):
    STOP = 0
    START = auto()
    FETCH = auto()

# --- Error's strings ---
ERR_ESP8266_NOT_CONNECTED = '(ERR) ESP8266 not connected. Please establish a connection first.'
ERR_INVALID_ACK = "(ERR) Received invalid acknowledgement: expected ACK ({ack_val}) or ERR ({err_val}), got {received_val}."
ERR_TIMEOUT_ACK = "(ERR) Timeout: No acknowledgement received from ESP8266."
ERR_CONNECTION_FAILED = "(ERR) Failed to connect to ESP8266 on port {port}: {error_msg}"
ERR_GENERIC_CONNECTION = "(ERR) An unexpected error occurred during connection: {error_msg}"
ERR_COMMUNICATION = "(ERR) Communication error: An issue occurred while sending or receiving data."
ERR_DEAUTH_START_FAILED = "(ERR) Failed to start deauthentication process."
ERR_SNIFF_START_FAILED = "(ERR) Failed to start sniffing process."
ERR_SNIFF_STOP_FAILED = "(ERR) Failed to stop sniffing process."
ERR_SNIFF_FETCH_FAILED = "(ERR) Failed to fetch sniffing data."
ERR_DEAUTH_STOP_FAILED = "(ERR) Failed to stop deauthentication process."
ERR_PING_FAILED = "(ERR) Failed to ping ESP8266."
ERR_INFO_FETCH_FAILED = "(ERR) Failed to fetch device information."
ERR_CLOSING_CONNECTION = "(ERR) Error occurred while closing the serial connection: {error_msg}"

# --- Custom Exception classes ---
class SerialEsp8266Error(Exception): pass

class SerialConnectionError(SerialEsp8266Error):
    def __init__(self, message="Connection ERROR: error occourred while connecting to ESP8266"):
        super().__init__(message)

class SerialCommunicationError(SerialEsp8266Error):
    def __init__(self, message="Communication ERROR: occourred while sending/receiving datas"):
        super().__init__(message)

class SerialTimeoutError(SerialCommunicationError):
    def __init__(self, message="Timeout ERROR: timeout reached while trying to recv datas"):
        super().__init__(message)

class SerialEsp8266:
    """My protocol"""
    def __init__(self, port=DEFAULT_SERIAL_PORT, baudrate=DEFAULT_BAUD_RATE, timeout=DEFAULT_TIMEOUT):
        """
        Inizializza l'oggetto SerialEsp8266.

        Args:
            port (str): es. '/dev/ttyUSB0', 'COM3'.
            baudrate (int)
            timeout (int/float): Timeout for serial operations.
        """
        self._port = port
        self._baudrate = baudrate
        self._timeout = timeout
        self._bytesize=serial.EIGHTBITS
        self._ser = None

    def _flush_and_wait_ack(self, timeout=1):
        self._ser.flush()
        start_time = time.time()
        while (time.time() - start_time) < timeout:
            if(self._ser.in_waiting == 1):
                c = int.from_bytes(self._ser.read())
                if(c == CMD.ACK.value): return True
                elif(int(c) == CMD.ERR.value): return False
                else: raise SerialCommunicationError(
                    ERR_INVALID_ACK.format(ack_val=CMD.ACK.value,err_val=CMD.ERR.value,received_val=c)
                    )
            time.sleep(0.1)
        raise SerialTimeoutError(ERR_TIMEOUT_ACK)

    # --- PUBBLIC METHODS ---
    @property
    def is_connected(self): return (self._ser is not None) and (self._ser.is_open)

    def connect(self):
        """Attempts to establish serial connection"""    
        try:
            self._ser = serial.Serial(
                port=self._port,
                baudrate=self._baudrate,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                bytesize=self._bytesize,
                timeout=self._timeout
            )
            time.sleep(1)
            self._ser.reset_input_buffer() #clear the buffer
            self._ser.reset_output_buffer()
            return True
        except serial.SerialException as e: raise SerialConnectionError(ERR_CONNECTION_FAILED.format(port=self._port, error_msg=e)) from e
        except Exception as e: raise SerialConnectionError(ERR_GENERIC_CONNECTION.format(error_msg=e)) from e

    def sniff_start(self):
        if not self.is_connected: raise SerialCommunicationError(ERR_ESP8266_NOT_CONNECTED)
        try:
            raw_bytes = bytearray()
            raw_bytes.append(CMD.SNIFF.value)
            raw_bytes.append(ARG.START.value)
            self._ser.write(raw_bytes)
            return self._flush_and_wait_ack()
        except Exception as e: print(e)
        
    def sniff_stop(self):
        if not self.is_connected: raise SerialCommunicationError(ERR_ESP8266_NOT_CONNECTED)
        try: 
            raw_bytes = bytearray()
            raw_bytes.append(CMD.SNIFF.value)
            raw_bytes.append(ARG.STOP.value)
            self._ser.write(raw_bytes)
            return self._flush_and_wait_ack()
        except Exception as e: raise Exception from e

    def sniff_fetch(self, ap_list:list[AP_fingerprint_t], sta_list:list[STA_fingerprint_t]):
        if not self.is_connected: raise SerialCommunicationError(ERR_ESP8266_NOT_CONNECTED)
        try:
            raw_bytes = bytearray()
            raw_bytes.append(CMD.SNIFF.value)
            raw_bytes.append(ARG.FETCH.value)
            self._ser.write(raw_bytes)
            #receiving...
            n = int.from_bytes(self._ser.read(1))
            for _ in range(0,n):
                ap = AP_fingerprint_t()
                ap.rssi = int.from_bytes(self._ser.read(1))
                ssid_len = int.from_bytes(self._ser.read(1))
                ap.ssid = self._ser.read(ssid_len)
                ap.mac = self._ser.read(6)
                ap.bssid = self._ser.read(6)
                ap.channel = int.from_bytes(self._ser.read(1))
                ap.data_channel = int.from_bytes(self._ser.read(1))
                ap.capability_info = int.from_bytes(self._ser.read(2))
                ap.encryption = int.from_bytes(self._ser.read(1))
                nn = int.from_bytes(self._ser.read(1))
                for _ in range(nn):
                    ap.linked_sta_macs.append(self._ser.read(6))
                ap_list.append(ap)

            n = int.from_bytes(self._ser.read(1))
            for _ in range(0,n):
                sta = STA_fingerprint_t()
                sta.rssi = int.from_bytes(self._ser.read(1))
                sta.mac  = self._ser.read(6)
                sta.broadcast = int.from_bytes(self._ser.read(1))
                ssid_len = int.from_bytes(self._ser.read(1))
                sta.ssid_ap = self._ser.read(ssid_len)
                sta.channel = int.from_bytes(self._ser.read(1))
                sta.data_channel = int.from_bytes(self._ser.read(1))
                nn = int.from_bytes(self._ser.read(1))
                for _ in range(nn):
                    sta.linked_ap_macs.append(self._ser.read(6))
                sta_list.append(sta)
        except Exception as e: raise Exception from e

    def deauth_start(self, channel: int, source: bytearray, dest = [0xff]*6):
        if not self.is_connected: raise SerialCommunicationError(ERR_ESP8266_NOT_CONNECTED)
        try:
            raw_bytes = bytearray()
            raw_bytes.append(CMD.DEAUTH.value)
            raw_bytes.append(ARG.START.value)
            raw_bytes.append(channel)
            raw_bytes += source + dest
            self._ser.write(raw_bytes)
            return self._flush_and_wait_ack()
        except Exception as e: raise Exception from e

    def deauth_stop(self):
        if not self.is_connected: raise SerialCommunicationError(ERR_ESP8266_NOT_CONNECTED)
        try:
            raw_bytes = bytearray()
            raw_bytes.append(CMD.DEAUTH.value)
            raw_bytes.append(ARG.STOP.value)
            self._ser.write(raw_bytes)
            return self._flush_and_wait_ack()
        except Exception as e: raise Exception from e

    def ping(self):
        if not self.is_connected: raise SerialCommunicationError(ERR_ESP8266_NOT_CONNECTED)
        try:
            raw_bytes = bytearray()
            raw_bytes.append(CMD.PING.value)
            self._ser.write(raw_bytes)
            self._ser.flush()
            return self._flush_and_wait_ack()
        except Exception as e: raise Exception from e
    
    def info(self):
        if not self.is_connected: raise SerialCommunicationError(ERR_ESP8266_NOT_CONNECTED)
        try:
            raw_bytes = bytearray()
            raw_bytes.append(CMD.INFO.value)
            self._ser.write(raw_bytes)
            self._ser.flush()
            return int.from_bytes(self._ser.read(1)), int.from_bytes(self._ser.read(1))
        except Exception as e: raise Exception from e

    def close(self):
        if not self.is_connected: raise SerialCommunicationError(ERR_ESP8266_NOT_CONNECTED)
        try:
            self._ser.close()
            self._ser = None
            return True
        except serial.SerialException as e: raise SerialConnectionError(ERR_CLOSING_CONNECTION.format(error_msg=e))