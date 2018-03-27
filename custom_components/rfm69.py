import logging

import voluptuous as vol

from homeassistant.const import (
    EVENT_HOMEASSISTANT_START, EVENT_HOMEASSISTANT_STOP)
from homeassistant.const import CONF_ENTITY_ID
import homeassistant.helpers.config_validation as cv

REQUIREMENTS = ['spidev','RPi.GPIO']

import time
import threading
import collections



_LOGGER = logging.getLogger(__name__)

RADIO = None

DOMAIN = 'rfm69'

CONF_NETWORK_ID = 'network_id'
CONF_NODE_ID = 'node_id'
CONF_SECRET = 'secret'

CONFIG_SCHEMA = vol.Schema({
    DOMAIN: vol.Schema({
        vol.Required(CONF_NETWORK_ID): cv.positive_int,
        vol.Required(CONF_NODE_ID): cv.positive_int,
        vol.Required(CONF_SECRET): cv.string,
    })
}, extra=vol.ALLOW_EXTRA)


def setup(hass, config):
    """Set up the RFM69 chip."""
    global RADIO

    network_id = config[DOMAIN][CONF_NETWORK_ID]
    node_id = config[DOMAIN][CONF_NODE_ID]
    aes_encrypt_key = config[DOMAIN][CONF_SECRET]

    RADIO = Rfm69hcw(network_id, node_id, aes_encrypt_key)

    def stop_service(event):
        """Stop the RFM69 chip."""
        _LOGGER.warning("Stopping RFM69 service.")
        if RADIO is not None:
            RADIO.shutdown()

        hass.bus.listen_once(EVENT_HOMEASSISTANT_START, start_service)

    def start_service(event):
        """Start the RFM69 chip."""
        _LOGGER.warning("Starting RFM69 service.")
        hass.bus.listen_once(EVENT_HOMEASSISTANT_STOP, stop_service)

    hass.bus.listen_once(EVENT_HOMEASSISTANT_START, start_service)

    return True


class ExpireQueue:

    def __init__(self, timeout=10):
        self._timeout = timeout              # Message timeout
        self._queue   = collections.deque()  # Message queue
        self._cv_waiting = threading.Condition()

    def _flush(self, t_curr):
        while self._queue and t_curr - self._queue[0][1] > self._timeout:
            self._queue.popleft()

    def put(self, item):
        """
        Push item to queue.
        """
        with self._cv_waiting:
            t_curr = time.time()
            self._flush(t_curr)
            self._queue.append((item, t_curr))
            self._cv_waiting.notify(1)

    def get(self, block=False, timeout=1.0):
        """
        Pop item from queue.

        Args:
            block          (Bool)  - If True, wait for message. If False, return immediately.
            timeout        (float) - Seconds to block on message.

        Returns:
            (item, t_wait) - Seconds item was left in the queue.
        """
        t_start = time.time()

        with self._cv_waiting:
            t_curr = time.time()
            self._flush(t_curr)

            # Immediate try
            if self._queue:
                item = self._queue.popleft()
                return item[0]
            if not block:
                return None

            # Wait until timeout or signal
            self._cv_waiting.wait(timeout)
            if self._queue:
                item = self._queue.popleft()
                return item[0]
            return None


class Rfm69hcw(object):
    """Representation of an RFM69HCW chip."""

    MESSAGE_EXPIRE_SEC = 5
    CACHE_EXPIRE_SEC = 20

    def __init__(self, network_id, node_id, aes_encrypt_key=None):
        self._rfm69 = RFM69(RF69_915MHZ, node_id, network_id, intPin=15, rstPin=13, interrupt_callback=self._receive)
        self._rfm69.setPowerLevel(pa_level=1, power=RF_PALEVEL_OUTPUTPOWER_10000)

        if aes_encrypt_key is not None:
            # Encryption key must be 16 bytes
            if len(aes_encrypt_key) < 16:
                aes_encrypt_key = aes_encrypt_key + '\0' * (16 - len(aes_encrypt_key))
            elif len(aes_encrypt_key) > 16:
                aes_encrypt_key = aes_encrypt_key[:16]
            self._rfm69.encrypt(aes_encrypt_key)
        self._responses = {}
        self._cache = {}
        self.add_device(255) # Broadcast node id

        self._rfm69.startListening()

    def add_device(self, node_id):
        self._responses[node_id] = ExpireQueue(self.MESSAGE_EXPIRE_SEC)

    def _receive(self, data, ack_received, id_sender, rssi):
        if id_sender in self._responses:
            _LOGGER.warning("Rfm69hcw._receive(): Received message {0} from node {1} with RSSI {2}.".format(data, id_sender, rssi))
            self._responses[id_sender].put(data)
        else:
            _LOGGER.warning("Rfm69hcw._receive(): Discarded message {0} from node {1} with RSSI {2}.".format(data, id_sender, rssi))

    def receive_message(self, id_sender, time_wait_sec=1.0, message_to_cache=None):
        """
        Args:
            node_id
            time_wait_sec - if None, wait indefinitely
        """
        response = self._responses[id_sender].get(True, time_wait_sec)
        if response is None:
            _LOGGER.warning("Rfm69hcw.receive_message(): Unable to receive message from node %d" % id_sender)
        elif message_to_cache is not None:
            # _LOGGER.warning("receive_message(): caching {0} in {1}".format(response, message_to_cache))
            self._cache[message_to_cache] = (response, time.time())

        return response

    def send_message(self, id_target, message, time_wait_sec=1.0, num_retries=3, cache=False, message_to_cache=None):
        # Fetch from cache
        if cache and message in self._cache and time.time() - self._cache[message][1] < self.CACHE_EXPIRE_SEC:
            # _LOGGER.warning("send_message(): cache {0} from {1}".format(self._cache[message], message))
            return self._cache[message][0]

        try:
            for i in range(num_retries):
                _LOGGER.warning("send_message(): Sending {0} {1} out of {2}.".format(message, i+1, num_retries))
                self._rfm69.send(id_target, message)
                reply = self.receive_message(id_target, time_wait_sec, message_to_cache)

                if reply is not None:
                    # _LOGGER.warning("send_message(): received {0}".format(message))
                    return reply
        except RuntimeError as err:
            _LOGGER.warning(err)

        _LOGGER.warning("Rfm69hcw.send_message(): Unable to send message \"%s\" to node %d" % (message, id_target))
        return None

    def shutdown(self):
        self._rfm69.shutdown()


class RFM69(object):

    def __init__(self, freqBand, nodeID, networkID, intPin=18, rstPin=28, spiBus=0, spiDevice=0, interrupt_callback=None):
        import spidev
        import RPi.GPIO as GPIO
        from queue import Queue

        self.freqBand = freqBand
        self.address = nodeID
        self.networkID = networkID
        self.isRFM69HW = False
        self.intPin = intPin
        self.rstPin = rstPin
        self.spiBus = spiBus
        self.spiDevice = spiDevice

        self.lock = threading.RLock()
        self.mode = ""
        self.promiscuousMode = False
        self.queue_data = Queue()
        self.sema_data_received = threading.Semaphore()
        self.sema_data_sent = threading.Semaphore()
        self.callback = interrupt_callback

        GPIO.cleanup()
        GPIO.setmode(GPIO.BOARD)
        GPIO.setup(self.intPin, GPIO.IN)
        GPIO.setup(self.rstPin, GPIO.OUT)

        self.CONFIG = {
          0x01: [REG_OPMODE, RF_OPMODE_SEQUENCER_ON | RF_OPMODE_LISTEN_OFF | RF_OPMODE_STANDBY],
          # No shaping
          0x02: [REG_DATAMODUL, RF_DATAMODUL_DATAMODE_PACKET | RF_DATAMODUL_MODULATIONTYPE_FSK | RF_DATAMODUL_MODULATIONSHAPING_00],
          # Default:4.8 KBPS
          0x03: [REG_BITRATEMSB, RF_BITRATEMSB_4800], # Default: 55555
          0x04: [REG_BITRATELSB, RF_BITRATELSB_4800],
          # Default:5khz, (FDEV + BitRate/2 <= 500Khz)
          0x05: [REG_FDEVMSB, RF_FDEVMSB_5000], # Default: 50000
          0x06: [REG_FDEVLSB, RF_FDEVLSB_5000],

          0x07: [REG_FRFMSB, RF69_FRFMSB[freqBand]],
          0x08: [REG_FRFMID, RF69_FRFMID[freqBand]],
          0x09: [REG_FRFLSB, RF69_FRFLSB[freqBand]],

          # Looks like PA1 and PA2 are not implemented on RFM69W, hence the max output power is 13dBm
          # +17dBm and +20dBm are possible on RFM69HW
          # +13dBm formula: Pout=-18+OutputPower (with PA0 or PA1**)
          # +17dBm formula: Pout=-14+OutputPower (with PA1 and PA2)**
          # +20dBm formula: Pout=-11+OutputPower (with PA1 and PA2)** and high power PA settings (section 3.3.7 in datasheet)
          0x11: [REG_PALEVEL, RF_PALEVEL_PA0_ON | RF_PALEVEL_PA1_OFF | RF_PALEVEL_PA2_OFF | RF_PALEVEL_OUTPUTPOWER_11111],
          # Over current protection (default is 95mA)
          # 0x13: [REG_OCP, RF_OCP_ON | RF_OCP_TRIM_95],

          # RXBW defaults are { REG_RXBW, RF_RXBW_DCCFREQ_010 | RF_RXBW_MANT_24 | RF_RXBW_EXP_5} (RxBw: 10.4khz)
          # (BitRate < 2 * RxBw)
          0x19: [REG_RXBW, RF_RXBW_DCCFREQ_010 | RF_RXBW_MANT_16 | RF_RXBW_EXP_2],
          # 0x1a: [REG_AFCBW, RF_AFCBW_DCCFREQAFC_010 | RF_AFCBW_MANTAFC_16 | RF_AFCBW_EXPAFC_2],
          # For BR-19200: //* 0x19 */ { REG_RXBW, RF_RXBW_DCCFREQ_010 | RF_RXBW_MANT_24 | RF_RXBW_EXP_3 },
          # DIO0 is the only IRQ we're using
          0x25: [REG_DIOMAPPING1, RF_DIOMAPPING1_DIO0_01],
          # DIO5 ClkOut disable for power saving
          0x26: [REG_DIOMAPPING2, RF_DIOMAPPING2_CLKOUT_OFF],
          # Writing to this bit ensures that the FIFO & status flags are reset
          0x28: [REG_IRQFLAGS2, RF_IRQFLAGS2_FIFOOVERRUN],
          # Must be set to dBm = (-Sensitivity / 2) - default is 0xE4=228 so -114dBm
          0x29: [REG_RSSITHRESH, 220],
          #  0x2d: { REG_PREAMBLELSB, RF_PREAMBLESIZE_LSB_VALUE } // default 3 preamble bytes 0xAAAAAA
          0x2e: [REG_SYNCCONFIG, RF_SYNC_ON | RF_SYNC_FIFOFILL_AUTO | RF_SYNC_SIZE_2 | RF_SYNC_TOL_0],
          # Attempt to make this compatible with sync1 byte of RFM12B lib
          0x2f: [REG_SYNCVALUE1, 0x2D],
          # NETWORK ID
          0x30: [REG_SYNCVALUE2, networkID],
          0x37: [REG_PACKETCONFIG1, RF_PACKET1_FORMAT_VARIABLE | RF_PACKET1_DCFREE_WHITENING |
                RF_PACKET1_CRC_ON | RF_PACKET1_CRCAUTOCLEAR_ON | RF_PACKET1_ADRSFILTERING_OFF],
          # In variable length mode: the max frame size, not used in TX
          0x38: [REG_PAYLOADLENGTH, 66],
          # 0x39: { REG_NODEADRS, nodeID }, //turned off because we're not using address filtering
          # TX on FIFO not empty
          0x3C: [REG_FIFOTHRESH, RF_FIFOTHRESH_TXSTART_FIFONOTEMPTY | RF_FIFOTHRESH_VALUE],
          # RXRESTARTDELAY must match transmitter PA ramp-down time (bitrate dependent)
          # TODO: Figure out PA ramp down
          0x3d: [REG_PACKETCONFIG2, RF_PACKET2_RXRESTARTDELAY_1BIT | RF_PACKET2_AUTORXRESTART_ON | RF_PACKET2_AES_OFF],
          # For BR-19200: //* 0x3d */ { REG_PACKETCONFIG2, RF_PACKET2_RXRESTARTDELAY_NONE | RF_PACKET2_AUTORXRESTART_ON | RF_PACKET2_AES_OFF }, //RXRESTARTDELAY must match transmitter PA ramp-down time (bitrate dependent)
          # 0x6F: { REG_TESTDAGC, RF_DAGC_CONTINUOUS }, // run DAGC continuously in RX mode
          # Run DAGC continuously in RX mode, recommended default for AfcLowBetaOn=0
          0x6F: [REG_TESTDAGC, RF_DAGC_IMPROVED_LOWBETA0],
          0x00: [255, 0]
        }

        #initialize SPI
        self.spi = spidev.SpiDev()
        self.spi.open(self.spiBus, self.spiDevice)
        self.spi.max_speed_hz = 4000000

        # Hard reset the RFM module
        GPIO.output(self.rstPin, GPIO.HIGH);
        time.sleep(0.1)
        GPIO.output(self.rstPin, GPIO.LOW);
        time.sleep(0.1)

        #verify chip is syncing?
        while self.readReg(REG_SYNCVALUE1) != 0xAA:
            self.writeReg(REG_SYNCVALUE1, 0xAA)

        while self.readReg(REG_SYNCVALUE1) != 0x55:
            self.writeReg(REG_SYNCVALUE1, 0x55)

        #write config
        for value in self.CONFIG.values():
            self.writeReg(value[0], value[1])

        self.encrypt(0)
        # Wait for ModeReady
        while (self.readReg(REG_IRQFLAGS1) & RF_IRQFLAGS1_MODEREADY) == 0x00:
            pass

        GPIO.remove_event_detect(self.intPin)
        GPIO.add_event_detect(self.intPin, GPIO.RISING, callback=self.interruptHandler)

        self._thread_receive = threading.Thread(target=self._receive, daemon=True)

    def startListening(self):
        self._thread_receive.start()

    def setFrequency(self, FRF):
        self.writeReg(REG_FRFMSB, FRF >> 16)
        self.writeReg(REG_FRFMID, FRF >> 8)
        self.writeReg(REG_FRFLSB, FRF)

    def setMode(self, new_mode):
        with self.lock:
            if new_mode == self.mode or new_mode not in RF69_OPMODES:
                return

            self.writeReg(REG_OPMODE, (self.readReg(REG_OPMODE) & 0xE3) | RF69_OPMODES[new_mode])
            if self.isRFM69HW:
                if new_mode == RF69_MODE_TX:
                    self.setHighPowerRegs(True)
                elif new_mode == RF69_MODE_RX:
                    self.setHighPowerRegs(False)

            # We are using packet mode, so this check is not really needed but
            # waiting for mode ready is necessary when going from sleep because
            # the FIFO may not be immediately available from previous mode.
            while self.mode == RF69_MODE_SLEEP and (self.readReg(REG_IRQFLAGS1) & RF_IRQFLAGS1_MODEREADY) == 0x00:
                pass

            self.mode = new_mode

    def sleep(self):
        self.setMode(RF69_MODE_SLEEP)

    def setAddress(self, addr):
        self.address = addr
        self.writeReg(REG_NODEADRS, self.address)

    def setNetwork(self, networkID):
        self.networkID = networkID
        self.writeReg(REG_SYNCVALUE2, networkID)

    def send(self, id_target, data="", requestACK=False):
        self.sendFrame(id_target, data, requestACK, False)

    def sendACK(self, id_target, data=""):
        self.sendFrame(id_target, data, False, True)

    def sendFrame(self, id_target, data, requestACK, sendACK):
        # Prepare data
        if len(data) > RF69_MAX_DATA_LEN:
            data = data[:RF69_MAX_DATA_LEN]
        if isinstance(data, str):
            data = [int(ord(i)) for i in list(data)]

        # Prepare ack
        ack = 0
        if sendACK:
            ack = RFM69_CTL_SENDACK
        elif requestACK:
            ack = RFM69_CTL_REQACK

        with self.lock:
            # Avoid RX deadlocks TODO: look up
            self.writeReg(REG_PACKETCONFIG2, (self.readReg(REG_PACKETCONFIG2) & 0xFB) | RF_PACKET2_RXRESTART)

            # Turn off receiver to prevent reception while filling fifo
            self.setMode(RF69_MODE_STANDBY)

            # Wait for modeReady
            startTime = time.time()
            while (self.readReg(REG_IRQFLAGS1) & RF_IRQFLAGS1_MODEREADY) == 0x00:
                if time.time() - startTime > 1.0:
                    raise RuntimeError("sendFrame(): RFM69 not connected.")
                pass

            # DIO0 is "Packet Sent"
            self.writeReg(REG_DIOMAPPING1, RF_DIOMAPPING1_DIO0_00)

            # Transfer data
            self.spi.xfer2([REG_FIFO | 0x80, len(data) + 3, id_target, self.address, ack] + data)
            self.setMode(RF69_MODE_TX)

        # Wait for data transfer
        self.sema_data_sent.acquire()
        # _LOGGER.warning("sendFrame(): Sent {0}.".format(data))
        self.setMode(RF69_MODE_RX)

    def _receive(self):
        try:
            self.receiveBegin()
            while self.sema_data_received.acquire():
                data, byte_ctl, id_sender, rssi = self.queue_data.get()
                ack_received  = byte_ctl & RFM69_CTL_SENDACK
                ack_requested = byte_ctl & RFM69_CTL_REQACK
                if ack_requested:
                    self.sendACK(id_sender)
                if data or ack_received:
                    self.callback(data, ack_received, id_sender, rssi)
        except Exception as e:
            _LOGGER.error("_receive() ERROR: {0}".format(e))

    def interruptHandler(self, pin):
        # TODO: Use threading locks?
        # _LOGGER.warning("Interrupt on pin %d in mode %d" % (pin, self.mode))
        with self.lock:
            if self.mode == RF69_MODE_TX:
                self.sema_data_sent.release()
                return

            if self.mode == RF69_MODE_RX and self.readReg(REG_IRQFLAGS2) & RF_IRQFLAGS2_PAYLOADREADY:
                self.setMode(RF69_MODE_STANDBY)
                # PAYLOADLEN, TARGETID, SENDERID, CTLbyte
                len_payload, id_target, id_sender, byte_ctl = self.spi.xfer2([REG_FIFO & 0x7f,0,0,0,0])[1:]
                if len_payload > 66:
                    len_payload = 66
                if len_payload < 3 or (not self.promiscuousMode and id_target != self.address and id_target != RF69_BROADCAST_ADDR):
                    self.receiveBegin()
                    return

                len_data = len_payload - 3
                data = self.spi.xfer2([REG_FIFO & 0x7f] + [0] * len_data)[1:] if len_data > 0 else []

                self.setMode(RF69_MODE_RX)
                rssi = self.readRSSI()

                self.queue_data.put((data, byte_ctl, id_sender, rssi))
                self.sema_data_received.release()

    def receiveBegin(self):
        if (self.readReg(REG_IRQFLAGS2) & RF_IRQFLAGS2_PAYLOADREADY):
            # Avoid RX deadlocks
            self.writeReg(REG_PACKETCONFIG2, (self.readReg(REG_PACKETCONFIG2) & 0xFB) | RF_PACKET2_RXRESTART)
        # Set DIO0 to "PAYLOADREADY" in receive mode
        self.writeReg(REG_DIOMAPPING1, RF_DIOMAPPING1_DIO0_01)
        self.setMode(RF69_MODE_RX)

    def encrypt(self, key):
        self.setMode(RF69_MODE_STANDBY)
        aes_config = RF_PACKET2_AES_OFF
        if key != 0 and len(key) == 16:
            self.spi.xfer([REG_AESKEY1 | 0x80] + [int(ord(i)) for i in list(key)])
            aes_config = RF_PACKET2_AES_ON

        self.writeReg(REG_PACKETCONFIG2,(self.readReg(REG_PACKETCONFIG2) & 0xFE) | aes_config)

    def readRSSI(self, forceTrigger=False):
        rssi = 0
        if forceTrigger:
            self.writeReg(REG_RSSICONFIG, RF_RSSI_START)
            while self.readReg(REG_RSSICONFIG) & RF_RSSI_DONE == 0x00:
                pass
        rssi = -self.readReg(REG_RSSIVALUE)
        rssi = rssi >> 1
        return rssi

    def readReg(self, addr):
        return self.spi.xfer([addr & 0x7F, 0])[1]

    def writeReg(self, addr, value):
        self.spi.xfer([addr | 0x80, value])

    def promiscuous(self, onOff):
        self.promiscuousMode = onOff

    def setPowerLevel(self, pa_level=0, power=0x1F):
        """
        Args:
            power: [0, 31]
            PA0:            Pout = -18 + power [dBm] [-18, +13]
            PA1:            Pout = -18 + power [dBm] [-2, +13]
            PA1 + PA2:      Pout = -14 + power [dBm] [+2, +17]
            PA1 + PA2 + HP: Pout = -11 + power [dBm] [+5, +20]
        """
        power = max(RF_PALEVEL_OUTPUTPOWER_00000, min(RF_PALEVEL_OUTPUTPOWER_11111, power))
        if pa_level == 0:  # PA0
            self.writeReg(REG_OCP, RF_OCP_ON)
            self.writeReg(REG_PALEVEL, RF_PALEVEL_PA0_ON | power)
        elif pa_level == 1:  # PA1
            self.writeReg(REG_OCP, RF_OCP_ON)
            self.writeReg(REG_PALEVEL, RF_PALEVEL_PA1_ON | power)
        elif pa_level == 2:  # PA1 + PA2
            self.writeReg(REG_OCP, RF_OCP_OFF)
            self.writeReg(REG_PALEVEL, RF_PALEVEL_PA1_ON | RF_PALEVEL_PA2_ON | power)

    def setHighPowerRegs(self, onOff):
        """
        High power adds +3 dBm to PA1 + PA2 TX strength. Must be turned off for RX mode!
        """
        if onOff:
            self.writeReg(REG_TESTPA1, 0x5D)
            self.writeReg(REG_TESTPA2, 0x7C)
        else:
            self.writeReg(REG_TESTPA1, 0x55)
            self.writeReg(REG_TESTPA2, 0x70)

    def readAllRegs(self):
        results = []
        for address in range(1, 0x50):
            results.append([str(hex(address)), str(hex(self.readReg(address)))])
        return results

    def readTemperature(self, calFactor):
        self.setMode(RF69_MODE_STANDBY)
        self.writeReg(REG_TEMP1, RF_TEMP1_MEAS_START)
        while self.readReg(REG_TEMP1) & RF_TEMP1_MEAS_RUNNING:
            pass
        # COURSE_TEMP_COEF puts reading in the ballpark, user can add additional correction
        #'complement'corrects the slope, rising temp = rising val
        return (int(~self.readReg(REG_TEMP2)) * -1) + COURSE_TEMP_COEF + calFactor


    def rcCalibration(self):
        self.writeReg(REG_OSC1, RF_OSC1_RCCAL_START)
        while self.readReg(REG_OSC1) & RF_OSC1_RCCAL_DONE == 0x00:
            pass

    def shutdown(self):
        import RPi.GPIO as GPIO
        self.setHighPower(False)
        self.sleep()
        GPIO.cleanup()

REG_FIFO          = 0x00  # FIFO read/write access
REG_OPMODE        = 0x01  # Operating modes of the transceiver
REG_DATAMODUL     = 0x02  # Data operation mode and Modulation settings
REG_BITRATEMSB    = 0x03  # Bit rate setting, Most Significant Bits
REG_BITRATELSB    = 0x04  # Bit rate setting, Least Significant Bits
REG_FDEVMSB       = 0x05  # Frequency Deviation setting, Most Significant Bits
REG_FDEVLSB       = 0x06  # Frequency Deviation setting, Least Significant Bits
REG_FRFMSB        = 0x07  # RF Carrier Frequency, Most Significant Bits
REG_FRFMID        = 0x08  # RF Carrier Frequency, Intermediate Bits
REG_FRFLSB        = 0x09  # RF Carrier Frequency, Least Significant Bits
REG_OSC1          = 0x0A  # RC Oscillator Settings
REG_AFCCTRL       = 0x0B  # AFC control in low modulation index situations
REG_LOWBAT        = 0x0C  # - reserved
REG_LISTEN1       = 0x0D  # Listen Mode settings
REG_LISTEN2       = 0x0E  # Listen Mode Idle duration
REG_LISTEN3       = 0x0F  # Listen Mode RX duration
REG_VERSION       = 0x10
REG_PALEVEL       = 0x11  # PA selection and Output Power control
REG_PARAMP        = 0x12  # Control of the PA ramp time in FSK mode
REG_OCP           = 0x13  # Over Current Protection control
REG_AGCREF        = 0x14  # - reserved
REG_AGCTHRESH1    = 0x15  # - reserved
REG_AGCTHRESH2    = 0x16  # - reserved
REG_AGCTHRESH3    = 0x17  # - reserved
REG_LNA           = 0x18  # LNA settings
REG_RXBW          = 0x19  # Channel Filter BW Control
REG_AFCBW         = 0x1A  # Channel Filter BW control during the AFC routine
REG_OOKPEAK       = 0x1B  # OOK demodulator selection and control in peak mode
REG_OOKAVG        = 0x1C  # Average threshold control of the OOK demodulator
REG_OOKFIX        = 0x1D  # Fixed threshold control of the OOK demodulator
REG_AFCFEI        = 0x1E  # AFC and FEI control and status
REG_AFCMSB        = 0x1F  # MSB of the frequency correction of the AFC
REG_AFCLSB        = 0x20  # LSB of the frequency correction of the AFC
REG_FEIMSB        = 0x21  # MSB of the calculated frequency error
REG_FEILSB        = 0x22  # LSB of the calculated frequency error
REG_RSSICONFIG    = 0x23  # RSSI-related settings
REG_RSSIVALUE     = 0x24  # RSSI value in dBm
REG_DIOMAPPING1   = 0x25  # Mapping of pins DIO0 to DIO3
REG_DIOMAPPING2   = 0x26  # Mapping of pins DIO4 and DIO5, ClkOut frequency
REG_IRQFLAGS1     = 0x27  # Status register: PLL Lock state, Timeout, RSSI > Threshold...
REG_IRQFLAGS2     = 0x28  # Status register: FIFO handling flags...
REG_RSSITHRESH    = 0x29  # RSSI Threshold control
REG_RXTIMEOUT1    = 0x2A  # Timeout duration between Rx request and RSSI detection
REG_RXTIMEOUT2    = 0x2B  # Timeout duration between RSSI detection and PayloadReady
REG_PREAMBLEMSB   = 0x2C  # Preamble length, MSB
REG_PREAMBLELSB   = 0x2D  # Preamble length, LSB
REG_SYNCCONFIG    = 0x2E  # Sync Word Recognition control
REG_SYNCVALUE1    = 0x2F  # Sync Word byte 1
REG_SYNCVALUE2    = 0x30  # Sync Word byte 2
REG_SYNCVALUE3    = 0x31  # Sync Word byte 3
REG_SYNCVALUE4    = 0x32  # Sync Word byte 4
REG_SYNCVALUE5    = 0x33  # Sync Word byte 5
REG_SYNCVALUE6    = 0x34  # Sync Word byte 6
REG_SYNCVALUE7    = 0x35  # Sync Word byte 7
REG_SYNCVALUE8    = 0x36  # Sync Word byte 8
REG_PACKETCONFIG1 = 0x37  # Packet mode settings
REG_PAYLOADLENGTH = 0x38  # Payload length setting
REG_NODEADRS      = 0x39  # Node address
REG_BROADCASTADRS = 0x3A  # Broadcast address
REG_AUTOMODES     = 0x3B  # Auto modes settings
REG_FIFOTHRESH    = 0x3C  # Fifo threshold, Tx start condition
REG_PACKETCONFIG2 = 0x3D  # Packet mode settings
REG_AESKEY1       = 0x3E  # Byte 1 of the cypher key
REG_AESKEY2       = 0x3F  # Byte 2 of the cypher key
REG_AESKEY3       = 0x40  # Byte 3 of the cypher key
REG_AESKEY4       = 0x41  # Byte 4 of the cypher key
REG_AESKEY5       = 0x42  # Byte 5 of the cypher key
REG_AESKEY6       = 0x43  # Byte 6 of the cypher key
REG_AESKEY7       = 0x44  # Byte 7 of the cypher key
REG_AESKEY8       = 0x45  # Byte 8 of the cypher key
REG_AESKEY9       = 0x46  # Byte 9 of the cypher key
REG_AESKEY10      = 0x47  # Byte 10 of the cypher key
REG_AESKEY11      = 0x48  # Byte 11 of the cypher key
REG_AESKEY12      = 0x49  # Byte 12 of the cypher key
REG_AESKEY13      = 0x4A  # Byte 13 of the cypher key
REG_AESKEY14      = 0x4B  # Byte 14 of the cypher key
REG_AESKEY15      = 0x4C  # Byte 15 of the cypher key
REG_AESKEY16      = 0x4D  # Byte 16 of the cypher key
REG_TEMP1         = 0x4E  # Temperature Sensor control
REG_TEMP2         = 0x4F  # Temperature readout
REG_TESTLNA       = 0x58  # Sensitivity boost
REG_TESTPA1       = 0x5A  # High Power PA settings (only present on RFM69HW/SX1231H)
REG_TESTPA2       = 0x5C  # High Power PA settings (only present on RFM69HW/SX1231H)
REG_TESTDAGC      = 0x6F  # Fading Margin Improvement
REG_TESTAFC       = 0x71  # AFC offset for low modulation index AFC

#******************************************************
# RF69/SX1231 bit control definition
#******************************************************

# RegOpMode (0x01)
RF_OPMODE_SEQUENCER_ON  = 0x00  # Default: Operation mode as selected with Mode bits in RegOpMode is automatically reached with the Sequencer
RF_OPMODE_SEQUENCER_OFF = 0x80  # Mode is forced by the user

RF_OPMODE_LISTEN_OFF    = 0x00  # Default: Off
RF_OPMODE_LISTEN_ON     = 0x40  # On

RF_OPMODE_LISTENABORT   = 0x20  # Aborts Listen mode when set together with ListenOn=0. Always reads 0.

RF_OPMODE_SLEEP         = 0x00  # Sleep mode (SLEEP)
RF_OPMODE_STANDBY       = 0x04  # Default: Standby mode (STDBY)
RF_OPMODE_SYNTHESIZER   = 0x08  # Frequency Synthesizer mode (FS)
RF_OPMODE_TRANSMITTER   = 0x0C  # Transmitter mode (TX)
RF_OPMODE_RECEIVER      = 0x10  # Receiver mode (RX)

# RegDataModul (0x02)
RF_DATAMODUL_DATAMODE_PACKET            = 0x00  # Default: Packet mode
RF_DATAMODUL_DATAMODE_CONTINUOUS        = 0x40  # Continuous mode with bit synchronizer
RF_DATAMODUL_DATAMODE_CONTINUOUSNOBSYNC = 0x60  # Continuous mode without bit synchronizer

RF_DATAMODUL_MODULATIONTYPE_FSK         = 0x00  # Default: FSK modulation scheme
RF_DATAMODUL_MODULATIONTYPE_OOK         = 0x08  # OOK modulation scheme

RF_DATAMODUL_MODULATIONSHAPING_00       = 0x00  # Default: No shaping
RF_DATAMODUL_MODULATIONSHAPING_01       = 0x01  # FSK: Gaussian filter, BT = 1.0; OOK: Filtering with f_cutoff = BR
RF_DATAMODUL_MODULATIONSHAPING_10       = 0x02  # FSK: Gaussian filter, BT = 0.5; OOK: Filtering with f_cutoff = 2*BR
RF_DATAMODUL_MODULATIONSHAPING_11       = 0x03  # FSK: Gaussian filter, BT = 0.3; OOK: Reserved

# RegBitRate (0x03, 0x04) - Bit Rate [bits/sec] (Chip Rate when Manchester encoding is enabled)
RF_BITRATEMSB_1200    = 0x68
RF_BITRATELSB_1200    = 0x2B
RF_BITRATEMSB_2400    = 0x34
RF_BITRATELSB_2400    = 0x15
RF_BITRATEMSB_4800    = 0x1A  # Default
RF_BITRATELSB_4800    = 0x0B  # Default
RF_BITRATEMSB_9600    = 0x0D
RF_BITRATELSB_9600    = 0x05
RF_BITRATEMSB_19200   = 0x06
RF_BITRATELSB_19200   = 0x83
RF_BITRATEMSB_38400   = 0x03
RF_BITRATELSB_38400   = 0x41

RF_BITRATEMSB_38323   = 0x03
RF_BITRATELSB_38323   = 0x43

RF_BITRATEMSB_34482   = 0x03
RF_BITRATELSB_34482   = 0xA0

RF_BITRATEMSB_76800   = 0x01
RF_BITRATELSB_76800   = 0xA1
RF_BITRATEMSB_153600  = 0x00
RF_BITRATELSB_153600  = 0xD0
RF_BITRATEMSB_57600   = 0x02
RF_BITRATELSB_57600   = 0x2C
RF_BITRATEMSB_115200  = 0x01
RF_BITRATELSB_115200  = 0x16
RF_BITRATEMSB_12500   = 0x0A
RF_BITRATELSB_12500   = 0x00
RF_BITRATEMSB_25000   = 0x05
RF_BITRATELSB_25000   = 0x00
RF_BITRATEMSB_50000   = 0x02
RF_BITRATELSB_50000   = 0x80
RF_BITRATEMSB_100000  = 0x01
RF_BITRATELSB_100000  = 0x40
RF_BITRATEMSB_150000  = 0x00
RF_BITRATELSB_150000  = 0xD5
RF_BITRATEMSB_200000  = 0x00
RF_BITRATELSB_200000  = 0xA0
RF_BITRATEMSB_250000  = 0x00
RF_BITRATELSB_250000  = 0x80
RF_BITRATEMSB_300000  = 0x00
RF_BITRATELSB_300000  = 0x6B
RF_BITRATEMSB_32768   = 0x03
RF_BITRATELSB_32768   = 0xD1
#custom bit rates
RF_BITRATEMSB_55555   = 0x02
RF_BITRATELSB_55555   = 0x40
RF_BITRATEMSB_200KBPS = 0x00
RF_BITRATELSB_200KBPS = 0xa0

# RegFdev (0x05, 0x06) - Frequency deviation [Hz]
RF_FDEVMSB_2000   = 0x00
RF_FDEVLSB_2000   = 0x21
RF_FDEVMSB_5000   = 0x00  # Default
RF_FDEVLSB_5000   = 0x52  # Default
RF_FDEVMSB_7500   = 0x00
RF_FDEVLSB_7500   = 0x7B
RF_FDEVMSB_10000  = 0x00
RF_FDEVLSB_10000  = 0xA4
RF_FDEVMSB_15000  = 0x00
RF_FDEVLSB_15000  = 0xF6
RF_FDEVMSB_20000  = 0x01
RF_FDEVLSB_20000  = 0x48
RF_FDEVMSB_25000  = 0x01
RF_FDEVLSB_25000  = 0x9A
RF_FDEVMSB_30000  = 0x01
RF_FDEVLSB_30000  = 0xEC
RF_FDEVMSB_35000  = 0x02
RF_FDEVLSB_35000  = 0x3D
RF_FDEVMSB_40000  = 0x02
RF_FDEVLSB_40000  = 0x8F
RF_FDEVMSB_45000  = 0x02
RF_FDEVLSB_45000  = 0xE1
RF_FDEVMSB_50000  = 0x03
RF_FDEVLSB_50000  = 0x33
RF_FDEVMSB_55000  = 0x03
RF_FDEVLSB_55000  = 0x85
RF_FDEVMSB_60000  = 0x03
RF_FDEVLSB_60000  = 0xD7
RF_FDEVMSB_65000  = 0x04
RF_FDEVLSB_65000  = 0x29
RF_FDEVMSB_70000  = 0x04
RF_FDEVLSB_70000  = 0x7B
RF_FDEVMSB_75000  = 0x04
RF_FDEVLSB_75000  = 0xCD
RF_FDEVMSB_80000  = 0x05
RF_FDEVLSB_80000  = 0x1F
RF_FDEVMSB_85000  = 0x05
RF_FDEVLSB_85000  = 0x71
RF_FDEVMSB_90000  = 0x05
RF_FDEVLSB_90000  = 0xC3
RF_FDEVMSB_95000  = 0x06
RF_FDEVLSB_95000  = 0x14
RF_FDEVMSB_100000 = 0x06
RF_FDEVLSB_100000 = 0x66
RF_FDEVMSB_110000 = 0x07
RF_FDEVLSB_110000 = 0x0A
RF_FDEVMSB_120000 = 0x07
RF_FDEVLSB_120000 = 0xAE
RF_FDEVMSB_130000 = 0x08
RF_FDEVLSB_130000 = 0x52
RF_FDEVMSB_140000 = 0x08
RF_FDEVLSB_140000 = 0xF6
RF_FDEVMSB_150000 = 0x09
RF_FDEVLSB_150000 = 0x9A
RF_FDEVMSB_160000 = 0x0A
RF_FDEVLSB_160000 = 0x3D
RF_FDEVMSB_170000 = 0x0A
RF_FDEVLSB_170000 = 0xE1
RF_FDEVMSB_180000 = 0x0B
RF_FDEVLSB_180000 = 0x85
RF_FDEVMSB_190000 = 0x0C
RF_FDEVLSB_190000 = 0x29
RF_FDEVMSB_200000 = 0x0C
RF_FDEVLSB_200000 = 0xCD
RF_FDEVMSB_210000 = 0x0D
RF_FDEVLSB_210000 = 0x71
RF_FDEVMSB_220000 = 0x0E
RF_FDEVLSB_220000 = 0x14
RF_FDEVMSB_230000 = 0x0E
RF_FDEVLSB_230000 = 0xB8
RF_FDEVMSB_240000 = 0x0F
RF_FDEVLSB_240000 = 0x5C
RF_FDEVMSB_250000 = 0x10
RF_FDEVLSB_250000 = 0x00
RF_FDEVMSB_260000 = 0x10
RF_FDEVLSB_260000 = 0xA4
RF_FDEVMSB_270000 = 0x11
RF_FDEVLSB_270000 = 0x48
RF_FDEVMSB_280000 = 0x11
RF_FDEVLSB_280000 = 0xEC
RF_FDEVMSB_290000 = 0x12
RF_FDEVLSB_290000 = 0x8F
RF_FDEVMSB_300000 = 0x13
RF_FDEVLSB_300000 = 0x33

# RegFrf (0x07, 0x08, 0x09) - Carrier frequency [MHz]
# 315Mhz band
RF_FRFMSB_314 = 0x4E
RF_FRFMID_314 = 0x80
RF_FRFLSB_314 = 0x00
RF_FRFMSB_315 = 0x4E
RF_FRFMID_315 = 0xC0
RF_FRFLSB_315 = 0x00
RF_FRFMSB_316 = 0x4F
RF_FRFMID_316 = 0x00
RF_FRFLSB_316 = 0x00
# 433mhz band
RF_FRFMSB_433 = 0x6C
RF_FRFMID_433 = 0x40
RF_FRFLSB_433 = 0x00
RF_FRFMSB_434 = 0x6C
RF_FRFMID_434 = 0x80
RF_FRFLSB_434 = 0x00
RF_FRFMSB_435 = 0x6C
RF_FRFMID_435 = 0xC0
RF_FRFLSB_435 = 0x00
# 868Mhz band
RF_FRFMSB_863 = 0xD7
RF_FRFMID_863 = 0xC0
RF_FRFLSB_863 = 0x00
RF_FRFMSB_864 = 0xD8
RF_FRFMID_864 = 0x00
RF_FRFLSB_864 = 0x00
RF_FRFMSB_865 = 0xD8
RF_FRFMID_865 = 0x40
RF_FRFLSB_865 = 0x00
RF_FRFMSB_866 = 0xD8
RF_FRFMID_866 = 0x80
RF_FRFLSB_866 = 0x00
RF_FRFMSB_867 = 0xD8
RF_FRFMID_867 = 0xC0
RF_FRFLSB_867 = 0x00
RF_FRFMSB_868 = 0xD9
RF_FRFMID_868 = 0x00
RF_FRFLSB_868 = 0x00
RF_FRFMSB_869 = 0xD9
RF_FRFMID_869 = 0x40
RF_FRFLSB_869 = 0x00
RF_FRFMSB_870 = 0xD9
RF_FRFMID_870 = 0x80
RF_FRFLSB_870 = 0x00
# 915Mhz band
RF_FRFMSB_902 = 0xE1
RF_FRFMID_902 = 0x80
RF_FRFLSB_902 = 0x00
RF_FRFMSB_903 = 0xE1
RF_FRFMID_903 = 0xC0
RF_FRFLSB_903 = 0x00
RF_FRFMSB_904 = 0xE2
RF_FRFMID_904 = 0x00
RF_FRFLSB_904 = 0x00
RF_FRFMSB_905 = 0xE2
RF_FRFMID_905 = 0x40
RF_FRFLSB_905 = 0x00
RF_FRFMSB_906 = 0xE2
RF_FRFMID_906 = 0x80
RF_FRFLSB_906 = 0x00
RF_FRFMSB_907 = 0xE2
RF_FRFMID_907 = 0xC0
RF_FRFLSB_907 = 0x00
RF_FRFMSB_908 = 0xE3
RF_FRFMID_908 = 0x00
RF_FRFLSB_908 = 0x00
RF_FRFMSB_909 = 0xE3
RF_FRFMID_909 = 0x40
RF_FRFLSB_909 = 0x00
RF_FRFMSB_910 = 0xE3
RF_FRFMID_910 = 0x80
RF_FRFLSB_910 = 0x00
RF_FRFMSB_911 = 0xE3
RF_FRFMID_911 = 0xC0
RF_FRFLSB_911 = 0x00
RF_FRFMSB_912 = 0xE4
RF_FRFMID_912 = 0x00
RF_FRFLSB_912 = 0x00
RF_FRFMSB_913 = 0xE4
RF_FRFMID_913 = 0x40
RF_FRFLSB_913 = 0x00
RF_FRFMSB_914 = 0xE4
RF_FRFMID_914 = 0x80
RF_FRFLSB_914 = 0x00
RF_FRFMSB_915 = 0xE4  # Default
RF_FRFMID_915 = 0xC0  # Default
RF_FRFLSB_915 = 0x00  # Default
RF_FRFMSB_916 = 0xE5
RF_FRFMID_916 = 0x00
RF_FRFLSB_916 = 0x00
RF_FRFMSB_917 = 0xE5
RF_FRFMID_917 = 0x40
RF_FRFLSB_917 = 0x00
RF_FRFMSB_918 = 0xE5
RF_FRFMID_918 = 0x80
RF_FRFLSB_918 = 0x00
RF_FRFMSB_919 = 0xE5
RF_FRFMID_919 = 0xC0
RF_FRFLSB_919 = 0x00
RF_FRFMSB_920 = 0xE6
RF_FRFMID_920 = 0x00
RF_FRFLSB_920 = 0x00
RF_FRFMSB_921 = 0xE6
RF_FRFMID_921 = 0x40
RF_FRFLSB_921 = 0x00
RF_FRFMSB_922 = 0xE6
RF_FRFMID_922 = 0x80
RF_FRFLSB_922 = 0x00
RF_FRFMSB_923 = 0xE6
RF_FRFMID_923 = 0xC0
RF_FRFLSB_923 = 0x00
RF_FRFMSB_924 = 0xE7
RF_FRFMID_924 = 0x00
RF_FRFLSB_924 = 0x00
RF_FRFMSB_925 = 0xE7
RF_FRFMID_925 = 0x40
RF_FRFLSB_925 = 0x00
RF_FRFMSB_926 = 0xE7
RF_FRFMID_926 = 0x80
RF_FRFLSB_926 = 0x00
RF_FRFMSB_927 = 0xE7
RF_FRFMID_927 = 0xC0
RF_FRFLSB_927 = 0x00
RF_FRFMSB_928 = 0xE8
RF_FRFMID_928 = 0x00
RF_FRFLSB_928 = 0x00


# RegOsc1 (0x0A)
RF_OSC1_RCCAL_START = 0x80  # Triggers the calibration of the RC oscillator when set. Always reads 0. RC calibration must be triggered in Standby mode.
RF_OSC1_RCCAL_DONE  = 0x40  # RC calibration is over

# RegLowBat (0x0C)
RF_LOWBAT_MONITOR = 0x10
RF_LOWBAT_ON = 0x08
RF_LOWBAT_OFF = 0x00  # Default

RF_LOWBAT_TRIM_1695 = 0x00
RF_LOWBAT_TRIM_1764 = 0x01
RF_LOWBAT_TRIM_1835 = 0x02  # Default
RF_LOWBAT_TRIM_1905 = 0x03
RF_LOWBAT_TRIM_1976 = 0x04
RF_LOWBAT_TRIM_2045 = 0x05
RF_LOWBAT_TRIM_2116 = 0x06
RF_LOWBAT_TRIM_2185 = 0x07


# RegListen1 (0x0D)
# Resolution of Listen mode Idle time
RF_LISTEN1_RESOL_64     = 0x50  # 64us
RF_LISTEN1_RESOL_4100   = 0xA0  # Default: 4.1ms
RF_LISTEN1_RESOL_262000 = 0xF0  # 262ms

# Criteria for packet acceptance in Listen mode
RF_LISTEN1_CRITERIA_RSSI        = 0x00  # Default: Signal strength is above RssiThreshold
RF_LISTEN1_CRITERIA_RSSIANDSYNC = 0x08  # Signal strength is above RssiThreshold and SyncAddress matched

# Action taken after acceptance of a packet in Listen mode
RF_LISTEN1_END_00 = 0x00  # Chip stays in Rx mode. Listen mode stops and must be disabled
RF_LISTEN1_END_01 = 0x02  # Default: Chip stays in Rx mode until PayloadReady or Timeout interrupt occurs. It then goes to the mode defined by Mode. Listen mode stops and must be disabled.
RF_LISTEN1_END_10 = 0x04  # Chip stays in Rx mode until PayloadReady or Timeout interrupt occurs. Listen mode then resumes in Idle state. FIFO content is lost at next Rx wakeup.


# RegListen2 (0x0E)
RF_LISTEN2_COEFIDLE_VALUE = 0xF5  # Default: Duration of the Idle phase in Listen mode

# RegListen3 (0x0F)
RF_LISTEN3_COEFRX_VALUE = 0x20 # Default: Duration of the Rx phase in Listen mode

# RegPaLevel (0x11)
RF_PALEVEL_PA0_ON  = 0x80  # Default: Enables PA0, connected to RFIO and LNA
RF_PALEVEL_PA0_OFF = 0x00  # Disables PA0
RF_PALEVEL_PA1_ON  = 0x40  # Enables PA1, on PA_BOOST pin
RF_PALEVEL_PA1_OFF = 0x00  # Default: Disables PA1
RF_PALEVEL_PA2_ON  = 0x20  # Enables PA2, on PA_BOOST pin
RF_PALEVEL_PA2_OFF = 0x00  # Default: Disables PA2

# Output power setting, with 1dB steps
# Pout = -18 + OutputPower [dBm], with PA0
# Pout = -18 + OutputPower [dBm], with PA1
# Pout = -14 + OutputPower [dBm], with PA1 and PA2
# Pout = -11 + OutputPower [dBm], with PA1 and PA2, and high power PA settings
RF_PALEVEL_OUTPUTPOWER_00000 = 0x00
RF_PALEVEL_OUTPUTPOWER_00001 = 0x01
RF_PALEVEL_OUTPUTPOWER_00010 = 0x02
RF_PALEVEL_OUTPUTPOWER_00011 = 0x03
RF_PALEVEL_OUTPUTPOWER_00100 = 0x04
RF_PALEVEL_OUTPUTPOWER_00101 = 0x05
RF_PALEVEL_OUTPUTPOWER_00110 = 0x06
RF_PALEVEL_OUTPUTPOWER_00111 = 0x07
RF_PALEVEL_OUTPUTPOWER_01000 = 0x08
RF_PALEVEL_OUTPUTPOWER_01001 = 0x09
RF_PALEVEL_OUTPUTPOWER_01010 = 0x0A
RF_PALEVEL_OUTPUTPOWER_01011 = 0x0B
RF_PALEVEL_OUTPUTPOWER_01100 = 0x0C
RF_PALEVEL_OUTPUTPOWER_01101 = 0x0D
RF_PALEVEL_OUTPUTPOWER_01110 = 0x0E
RF_PALEVEL_OUTPUTPOWER_01111 = 0x0F
RF_PALEVEL_OUTPUTPOWER_10000 = 0x10
RF_PALEVEL_OUTPUTPOWER_10001 = 0x11
RF_PALEVEL_OUTPUTPOWER_10010 = 0x12
RF_PALEVEL_OUTPUTPOWER_10011 = 0x13
RF_PALEVEL_OUTPUTPOWER_10100 = 0x14
RF_PALEVEL_OUTPUTPOWER_10101 = 0x15
RF_PALEVEL_OUTPUTPOWER_10110 = 0x16
RF_PALEVEL_OUTPUTPOWER_10111 = 0x17
RF_PALEVEL_OUTPUTPOWER_11000 = 0x18
RF_PALEVEL_OUTPUTPOWER_11001 = 0x19
RF_PALEVEL_OUTPUTPOWER_11010 = 0x1A
RF_PALEVEL_OUTPUTPOWER_11011 = 0x1B
RF_PALEVEL_OUTPUTPOWER_11100 = 0x1C
RF_PALEVEL_OUTPUTPOWER_11101 = 0x1D
RF_PALEVEL_OUTPUTPOWER_11110 = 0x1E
RF_PALEVEL_OUTPUTPOWER_11111 = 0x1F  # Default


# RegPaRamp (0x12) - Rise/Fall time of ramp up/down in FSK
RF_PARAMP_3400 = 0x00  # 3.4 ms
RF_PARAMP_2000 = 0x01  # 2 ms
RF_PARAMP_1000 = 0x02  # 1 ms
RF_PARAMP_500  = 0x03  # 500 us
RF_PARAMP_250  = 0x04  # 250 us
RF_PARAMP_125  = 0x05  # 125 us
RF_PARAMP_100  = 0x06  # 100 us
RF_PARAMP_62   = 0x07  # 62 us
RF_PARAMP_50   = 0x08  # 50 us
RF_PARAMP_40   = 0x09  # Default: 40 us
RF_PARAMP_31   = 0x0A  # 31 us
RF_PARAMP_25   = 0x0B  # 25 us
RF_PARAMP_20   = 0x0C  # 20 us
RF_PARAMP_15   = 0x0D  # 15 us
RF_PARAMP_12   = 0x0E  # 12 us
RF_PARAMP_10   = 0x0F  # 10 us


# RegOcp (0x13)
# Overload current protection (OCP) for the PA
RF_OCP_OFF = 0x0F  # OCP disabled
RF_OCP_ON  = 0x1A  # Default: OCP enabled

# Trimming of the OCP current
RF_OCP_TRIM_45  = 0x00
RF_OCP_TRIM_50  = 0x01
RF_OCP_TRIM_55  = 0x02
RF_OCP_TRIM_60  = 0x03
RF_OCP_TRIM_65  = 0x04
RF_OCP_TRIM_70  = 0x05
RF_OCP_TRIM_75  = 0x06
RF_OCP_TRIM_80  = 0x07
RF_OCP_TRIM_85  = 0x08
RF_OCP_TRIM_90  = 0x09
RF_OCP_TRIM_95  = 0x0A  # Default: 95 mA
RF_OCP_TRIM_100 = 0x0B
RF_OCP_TRIM_105 = 0x0C
RF_OCP_TRIM_110 = 0x0D
RF_OCP_TRIM_115 = 0x0E
RF_OCP_TRIM_120 = 0x0F


# RegAgcRef
RF_AGCREF_AUTO_ON  = 0x40  # Default
RF_AGCREF_AUTO_OFF = 0x00

RF_AGCREF_LEVEL_MINUS80  = 0x00  # Default
RF_AGCREF_LEVEL_MINUS81  = 0x01
RF_AGCREF_LEVEL_MINUS82  = 0x02
RF_AGCREF_LEVEL_MINUS83  = 0x03
RF_AGCREF_LEVEL_MINUS84  = 0x04
RF_AGCREF_LEVEL_MINUS85  = 0x05
RF_AGCREF_LEVEL_MINUS86  = 0x06
RF_AGCREF_LEVEL_MINUS87  = 0x07
RF_AGCREF_LEVEL_MINUS88  = 0x08
RF_AGCREF_LEVEL_MINUS89  = 0x09
RF_AGCREF_LEVEL_MINUS90  = 0x0A
RF_AGCREF_LEVEL_MINUS91  = 0x0B
RF_AGCREF_LEVEL_MINUS92  = 0x0C
RF_AGCREF_LEVEL_MINUS93  = 0x0D
RF_AGCREF_LEVEL_MINUS94  = 0x0E
RF_AGCREF_LEVEL_MINUS95  = 0x0F
RF_AGCREF_LEVEL_MINUS96  = 0x10
RF_AGCREF_LEVEL_MINUS97  = 0x11
RF_AGCREF_LEVEL_MINUS98  = 0x12
RF_AGCREF_LEVEL_MINUS99  = 0x13
RF_AGCREF_LEVEL_MINUS100 = 0x14
RF_AGCREF_LEVEL_MINUS101 = 0x15
RF_AGCREF_LEVEL_MINUS102 = 0x16
RF_AGCREF_LEVEL_MINUS103 = 0x17
RF_AGCREF_LEVEL_MINUS104 = 0x18
RF_AGCREF_LEVEL_MINUS105 = 0x19
RF_AGCREF_LEVEL_MINUS106 = 0x1A
RF_AGCREF_LEVEL_MINUS107 = 0x1B
RF_AGCREF_LEVEL_MINUS108 = 0x1C
RF_AGCREF_LEVEL_MINUS109 = 0x1D
RF_AGCREF_LEVEL_MINUS110 = 0x1E
RF_AGCREF_LEVEL_MINUS111 = 0x1F
RF_AGCREF_LEVEL_MINUS112 = 0x20
RF_AGCREF_LEVEL_MINUS113 = 0x21
RF_AGCREF_LEVEL_MINUS114 = 0x22
RF_AGCREF_LEVEL_MINUS115 = 0x23
RF_AGCREF_LEVEL_MINUS116 = 0x24
RF_AGCREF_LEVEL_MINUS117 = 0x25
RF_AGCREF_LEVEL_MINUS118 = 0x26
RF_AGCREF_LEVEL_MINUS119 = 0x27
RF_AGCREF_LEVEL_MINUS120 = 0x28
RF_AGCREF_LEVEL_MINUS121 = 0x29
RF_AGCREF_LEVEL_MINUS122 = 0x2A
RF_AGCREF_LEVEL_MINUS123 = 0x2B
RF_AGCREF_LEVEL_MINUS124 = 0x2C
RF_AGCREF_LEVEL_MINUS125 = 0x2D
RF_AGCREF_LEVEL_MINUS126 = 0x2E
RF_AGCREF_LEVEL_MINUS127 = 0x2F
RF_AGCREF_LEVEL_MINUS128 = 0x30
RF_AGCREF_LEVEL_MINUS129 = 0x31
RF_AGCREF_LEVEL_MINUS130 = 0x32
RF_AGCREF_LEVEL_MINUS131 = 0x33
RF_AGCREF_LEVEL_MINUS132 = 0x34
RF_AGCREF_LEVEL_MINUS133 = 0x35
RF_AGCREF_LEVEL_MINUS134 = 0x36
RF_AGCREF_LEVEL_MINUS135 = 0x37
RF_AGCREF_LEVEL_MINUS136 = 0x38
RF_AGCREF_LEVEL_MINUS137 = 0x39
RF_AGCREF_LEVEL_MINUS138 = 0x3A
RF_AGCREF_LEVEL_MINUS139 = 0x3B
RF_AGCREF_LEVEL_MINUS140 = 0x3C
RF_AGCREF_LEVEL_MINUS141 = 0x3D
RF_AGCREF_LEVEL_MINUS142 = 0x3E
RF_AGCREF_LEVEL_MINUS143 = 0x3F


# RegAgcThresh1
RF_AGCTHRESH1_SNRMARGIN_000 = 0x00
RF_AGCTHRESH1_SNRMARGIN_001 = 0x20
RF_AGCTHRESH1_SNRMARGIN_010 = 0x40
RF_AGCTHRESH1_SNRMARGIN_011 = 0x60
RF_AGCTHRESH1_SNRMARGIN_100 = 0x80
RF_AGCTHRESH1_SNRMARGIN_101 = 0xA0  # Default
RF_AGCTHRESH1_SNRMARGIN_110 = 0xC0
RF_AGCTHRESH1_SNRMARGIN_111 = 0xE0

RF_AGCTHRESH1_STEP1_0  = 0x00
RF_AGCTHRESH1_STEP1_1  = 0x01
RF_AGCTHRESH1_STEP1_2  = 0x02
RF_AGCTHRESH1_STEP1_3  = 0x03
RF_AGCTHRESH1_STEP1_4  = 0x04
RF_AGCTHRESH1_STEP1_5  = 0x05
RF_AGCTHRESH1_STEP1_6  = 0x06
RF_AGCTHRESH1_STEP1_7  = 0x07
RF_AGCTHRESH1_STEP1_8  = 0x08
RF_AGCTHRESH1_STEP1_9  = 0x09
RF_AGCTHRESH1_STEP1_10 = 0x0A
RF_AGCTHRESH1_STEP1_11 = 0x0B
RF_AGCTHRESH1_STEP1_12 = 0x0C
RF_AGCTHRESH1_STEP1_13 = 0x0D
RF_AGCTHRESH1_STEP1_14 = 0x0E
RF_AGCTHRESH1_STEP1_15 = 0x0F
RF_AGCTHRESH1_STEP1_16 = 0x10  # Default
RF_AGCTHRESH1_STEP1_17 = 0x11
RF_AGCTHRESH1_STEP1_18 = 0x12
RF_AGCTHRESH1_STEP1_19 = 0x13
RF_AGCTHRESH1_STEP1_20 = 0x14
RF_AGCTHRESH1_STEP1_21 = 0x15
RF_AGCTHRESH1_STEP1_22 = 0x16
RF_AGCTHRESH1_STEP1_23 = 0x17
RF_AGCTHRESH1_STEP1_24 = 0x18
RF_AGCTHRESH1_STEP1_25 = 0x19
RF_AGCTHRESH1_STEP1_26 = 0x1A
RF_AGCTHRESH1_STEP1_27 = 0x1B
RF_AGCTHRESH1_STEP1_28 = 0x1C
RF_AGCTHRESH1_STEP1_29 = 0x1D
RF_AGCTHRESH1_STEP1_30 = 0x1E
RF_AGCTHRESH1_STEP1_31 = 0x1F


# RegAgcThresh2
RF_AGCTHRESH2_STEP2_0  = 0x00
RF_AGCTHRESH2_STEP2_1  = 0x10
RF_AGCTHRESH2_STEP2_2  = 0x20
RF_AGCTHRESH2_STEP2_3  = 0x30  # XXX wrong -- Default
RF_AGCTHRESH2_STEP2_4  = 0x40
RF_AGCTHRESH2_STEP2_5  = 0x50
RF_AGCTHRESH2_STEP2_6  = 0x60
RF_AGCTHRESH2_STEP2_7  = 0x70	# default
RF_AGCTHRESH2_STEP2_8  = 0x80
RF_AGCTHRESH2_STEP2_9  = 0x90
RF_AGCTHRESH2_STEP2_10 = 0xA0
RF_AGCTHRESH2_STEP2_11 = 0xB0
RF_AGCTHRESH2_STEP2_12 = 0xC0
RF_AGCTHRESH2_STEP2_13 = 0xD0
RF_AGCTHRESH2_STEP2_14 = 0xE0
RF_AGCTHRESH2_STEP2_15 = 0xF0

RF_AGCTHRESH2_STEP3_0  = 0x00
RF_AGCTHRESH2_STEP3_1  = 0x01
RF_AGCTHRESH2_STEP3_2  = 0x02
RF_AGCTHRESH2_STEP3_3  = 0x03
RF_AGCTHRESH2_STEP3_4  = 0x04
RF_AGCTHRESH2_STEP3_5  = 0x05
RF_AGCTHRESH2_STEP3_6  = 0x06
RF_AGCTHRESH2_STEP3_7  = 0x07
RF_AGCTHRESH2_STEP3_8  = 0x08
RF_AGCTHRESH2_STEP3_9  = 0x09
RF_AGCTHRESH2_STEP3_10 = 0x0A
RF_AGCTHRESH2_STEP3_11 = 0x0B  # Default
RF_AGCTHRESH2_STEP3_12 = 0x0C
RF_AGCTHRESH2_STEP3_13 = 0x0D
RF_AGCTHRESH2_STEP3_14 = 0x0E
RF_AGCTHRESH2_STEP3_15 = 0x0F


# RegAgcThresh3
RF_AGCTHRESH3_STEP4_0  = 0x00
RF_AGCTHRESH3_STEP4_1  = 0x10
RF_AGCTHRESH3_STEP4_2  = 0x20
RF_AGCTHRESH3_STEP4_3  = 0x30
RF_AGCTHRESH3_STEP4_4  = 0x40
RF_AGCTHRESH3_STEP4_5  = 0x50
RF_AGCTHRESH3_STEP4_6  = 0x60
RF_AGCTHRESH3_STEP4_7  = 0x70
RF_AGCTHRESH3_STEP4_8  = 0x80
RF_AGCTHRESH3_STEP4_9  = 0x90  # Default
RF_AGCTHRESH3_STEP4_10 = 0xA0
RF_AGCTHRESH3_STEP4_11 = 0xB0
RF_AGCTHRESH3_STEP4_12 = 0xC0
RF_AGCTHRESH3_STEP4_13 = 0xD0
RF_AGCTHRESH3_STEP4_14 = 0xE0
RF_AGCTHRESH3_STEP4_15 = 0xF0

RF_AGCTHRESH3_STEP5_0  = 0x00
RF_AGCTHRESH3_STEP5_1  = 0x01
RF_AGCTHRESH3_STEP5_2  = 0x02
RF_AGCTHRESH3_STEP5_3  = 0x03
RF_AGCTHRESH3_STEP5_4  = 0x04
RF_AGCTHRESH3_STEP5_5  = 0x05
RF_AGCTHRESH3_STEP5_6  = 0x06
RF_AGCTHRESH3_STEP5_7  = 0x07
RF_AGCTHRES33_STEP5_8  = 0x08
RF_AGCTHRESH3_STEP5_9  = 0x09
RF_AGCTHRESH3_STEP5_10 = 0x0A
RF_AGCTHRESH3_STEP5_11 = 0x0B  # Default
RF_AGCTHRESH3_STEP5_12 = 0x0C
RF_AGCTHRESH3_STEP5_13 = 0x0D
RF_AGCTHRESH3_STEP5_14 = 0x0E
RF_AGCTHRESH3_STEP5_15 = 0x0F


# RegLna (0x18)
# LNA's input impedance
RF_LNA_ZIN_50  = 0x00  # 50 ohms
RF_LNA_ZIN_200 = 0x80  # Default: 200 ohms

RF_LNA_LOWPOWER_OFF = 0x00  # Default
RF_LNA_LOWPOWER_ON  = 0x40

RF_LNA_CURRENTGAIN = 0x08

RF_LNA_GAINSELECT_AUTO       = 0x00  # Default: Gain set by the internal AGC loop
RF_LNA_GAINSELECT_MAX        = 0x01  # G1 = highest gain
RF_LNA_GAINSELECT_MAXMINUS6  = 0x02  # G2 = highest gain - 6 dB
RF_LNA_GAINSELECT_MAXMINUS12 = 0x03  # G3 = highest gain - 12 dB
RF_LNA_GAINSELECT_MAXMINUS24 = 0x04  # G4 = highest gain - 24 dB
RF_LNA_GAINSELECT_MAXMINUS36 = 0x05  # G5 = highest gain - 36 dB
RF_LNA_GAINSELECT_MAXMINUS48 = 0x06  # G6 = highest gain - 48 dB


# RegRxBw (0x19)
# Cut-off frequency of the DC offset canceller
RF_RXBW_DCCFREQ_000 = 0x00
RF_RXBW_DCCFREQ_001 = 0x20
RF_RXBW_DCCFREQ_010 = 0x40  # Default
RF_RXBW_DCCFREQ_011 = 0x60
RF_RXBW_DCCFREQ_100 = 0x80
RF_RXBW_DCCFREQ_101 = 0xA0
RF_RXBW_DCCFREQ_110 = 0xC0
RF_RXBW_DCCFREQ_111 = 0xE0

# Channel filter bandwidth control
RF_RXBW_MANT_16 = 0x00
RF_RXBW_MANT_20 = 0x08
RF_RXBW_MANT_24 = 0x10  # Default

# Channel filter bandwidth control
RF_RXBW_EXP_0 = 0x00
RF_RXBW_EXP_1 = 0x01
RF_RXBW_EXP_2 = 0x02
RF_RXBW_EXP_3 = 0x03
RF_RXBW_EXP_4 = 0x04
RF_RXBW_EXP_5 = 0x05  # Default
RF_RXBW_EXP_6 = 0x06
RF_RXBW_EXP_7 = 0x07


# RegAfcBw (0x1A)
# DccFreq parameter used during the AFC
RF_AFCBW_DCCFREQAFC_000 = 0x00
RF_AFCBW_DCCFREQAFC_001 = 0x20
RF_AFCBW_DCCFREQAFC_010 = 0x40
RF_AFCBW_DCCFREQAFC_011 = 0x60
RF_AFCBW_DCCFREQAFC_100 = 0x80  # Default
RF_AFCBW_DCCFREQAFC_101 = 0xA0
RF_AFCBW_DCCFREQAFC_110 = 0xC0
RF_AFCBW_DCCFREQAFC_111 = 0xE0

# RxBwMant parameter used during the AFC
RF_AFCBW_MANTAFC_16 = 0x00
RF_AFCBW_MANTAFC_20 = 0x08  # Default
RF_AFCBW_MANTAFC_24 = 0x10

# RxBwExp parameter used during the AFC
RF_AFCBW_EXPAFC_0 = 0x00
RF_AFCBW_EXPAFC_1 = 0x01
RF_AFCBW_EXPAFC_2 = 0x02
RF_AFCBW_EXPAFC_3 = 0x03  # Default
RF_AFCBW_EXPAFC_4 = 0x04
RF_AFCBW_EXPAFC_5 = 0x05
RF_AFCBW_EXPAFC_6 = 0x06
RF_AFCBW_EXPAFC_7 = 0x07


# RegOokPeak (0x1B)
# Selects type of threshold in the OOK data slicer
RF_OOKPEAK_THRESHTYPE_FIXED   = 0x00
RF_OOKPEAK_THRESHTYPE_PEAK    = 0x40  # Default
RF_OOKPEAK_THRESHTYPE_AVERAGE = 0x80

# Size of each decrement of the RSSI threshold in the OOK demodulator
RF_OOKPEAK_PEAKTHRESHSTEP_000 = 0x00  # Default: 0.5 dB
RF_OOKPEAK_PEAKTHRESHSTEP_001 = 0x08  # 1.0 dB
RF_OOKPEAK_PEAKTHRESHSTEP_010 = 0x10  # 1.5 dB
RF_OOKPEAK_PEAKTHRESHSTEP_011 = 0x18  # 2.0 dB
RF_OOKPEAK_PEAKTHRESHSTEP_100 = 0x20  # 3.0 dB
RF_OOKPEAK_PEAKTHRESHSTEP_101 = 0x28  # 4.0 dB
RF_OOKPEAK_PEAKTHRESHSTEP_110 = 0x30  # 5.0 dB
RF_OOKPEAK_PEAKTHRESHSTEP_111 = 0x38  # 6.0 dB

# Period of decrement of the RSSI threshold in the OOK demodulator
RF_OOKPEAK_PEAKTHRESHDEC_000 = 0x00  # Default: Once per chip
RF_OOKPEAK_PEAKTHRESHDEC_001 = 0x01  # Once every 2 chips
RF_OOKPEAK_PEAKTHRESHDEC_010 = 0x02  # Once every 4 chips
RF_OOKPEAK_PEAKTHRESHDEC_011 = 0x03  # Once every 8 chips
RF_OOKPEAK_PEAKTHRESHDEC_100 = 0x04  # Twice in each chip
RF_OOKPEAK_PEAKTHRESHDEC_101 = 0x05  # 4 times in each chip
RF_OOKPEAK_PEAKTHRESHDEC_110 = 0x06  # 8 times in each chip
RF_OOKPEAK_PEAKTHRESHDEC_111 = 0x07  # 16 times in each chip


# RegOokAvg (0x1C)
# Filter coefficients in average mode of the OOK demodulator
RF_OOKAVG_AVERAGETHRESHFILT_00 = 0x00  # f_C = chip rate / 32.pi
RF_OOKAVG_AVERAGETHRESHFILT_01 = 0x40  # f_C = chip rate / 8.pi
RF_OOKAVG_AVERAGETHRESHFILT_10 = 0x80  # Default: f_C = chip rate / 4.pi
RF_OOKAVG_AVERAGETHRESHFILT_11 = 0xC0  # f_C = chip rate / 2.pi


# RegOokFix (0x1D)
# Fixed threshold value in the OOK demodulator [dB]. Used when OokThresType = 00
RF_OOKFIX_FIXEDTHRESH_VALUE = 0x06  # Default: 6 dB


# RegAfcFei (0x1E)
RF_AFCFEI_FEI_DONE         = 0x40  # FEI is on-going
RF_AFCFEI_FEI_START        = 0x20  # Triggers a FEI measurement when set. Always reads 0.
RF_AFCFEI_AFC_DONE         = 0x10  # AFC is on-going
RF_AFCFEI_AFCAUTOCLEAR_ON  = 0x08  # AFC register is cleared before a new AFC phase (only valid if AfcAutoOn is set)
RF_AFCFEI_AFCAUTOCLEAR_OFF = 0x00  # Default: AFC register is not cleared before a new AFC phase

RF_AFCFEI_AFCAUTO_ON  = 0x04  # AFC is performed each time Rx mode is entered
RF_AFCFEI_AFCAUTO_OFF = 0x00  # Default: AFC is performed each time AfcStart is set

RF_AFCFEI_AFC_CLEAR = 0x02  # Clears the AfcValue if set in Rx mode. Always reads 0.
RF_AFCFEI_AFC_START = 0x01  # Triggers an AFC when set. Always reads 0.

# RegRssiConfig (0x23)
RF_RSSI_FASTRX_ON  = 0x08
RF_RSSI_FASTRX_OFF = 0x00  # Default
RF_RSSI_DONE  = 0x02  # False: RSSI is on-going; True: RSSI sampling is finished, result available
RF_RSSI_START = 0x01  # Trigger a RSSI measurement when set. Always reads 0


# RegDioMapping1 (0x25) - Mapping of pins DIO0 to DIO3
RF_DIOMAPPING1_DIO0_00 = 0x00  # Default
RF_DIOMAPPING1_DIO0_01 = 0x40
RF_DIOMAPPING1_DIO0_10 = 0x80
RF_DIOMAPPING1_DIO0_11 = 0xC0

RF_DIOMAPPING1_DIO1_00 = 0x00  # Default
RF_DIOMAPPING1_DIO1_01 = 0x10
RF_DIOMAPPING1_DIO1_10 = 0x20
RF_DIOMAPPING1_DIO1_11 = 0x30

RF_DIOMAPPING1_DIO2_00 = 0x00  # Default
RF_DIOMAPPING1_DIO2_01 = 0x04
RF_DIOMAPPING1_DIO2_10 = 0x08
RF_DIOMAPPING1_DIO2_11 = 0x0C

RF_DIOMAPPING1_DIO3_00 = 0x00  # Default
RF_DIOMAPPING1_DIO3_01 = 0x01
RF_DIOMAPPING1_DIO3_10 = 0x02
RF_DIOMAPPING1_DIO3_11 = 0x03


# RegDioMapping2 (0x26)
# Mapping of pins DIO4 to DIO5
RF_DIOMAPPING2_DIO4_00 = 0x00  # Default
RF_DIOMAPPING2_DIO4_01 = 0x40
RF_DIOMAPPING2_DIO4_10 = 0x80
RF_DIOMAPPING2_DIO4_11 = 0xC0

RF_DIOMAPPING2_DIO5_00 = 0x00  # Default
RF_DIOMAPPING2_DIO5_01 = 0x10
RF_DIOMAPPING2_DIO5_10 = 0x20
RF_DIOMAPPING2_DIO5_11 = 0x30

# Selects CLKOUT frequency
RF_DIOMAPPING2_CLKOUT_32  = 0x00  # FXOSC
RF_DIOMAPPING2_CLKOUT_16  = 0x01  # FXOSC / 2
RF_DIOMAPPING2_CLKOUT_8   = 0x02  # FXOSC / 4
RF_DIOMAPPING2_CLKOUT_4   = 0x03  # FXOSC / 8
RF_DIOMAPPING2_CLKOUT_2   = 0x04  # FXOSC / 16
RF_DIOMAPPING2_CLKOUT_1   = 0x05  # FXOSC / 32
RF_DIOMAPPING2_CLKOUT_RC  = 0x06  # RC (automatically enabled)
RF_DIOMAPPING2_CLKOUT_OFF = 0x07  # Default


# RegIrqFlags1 (0x27)
RF_IRQFLAGS1_MODEREADY        = 0x80  # Set when the operation mode is ready {Sleep: Entering Sleep mode, Standby: XO is running, FS: PLL is locked, Rx: RSSI sampling starts, Tx: PA ramp-up completed}
RF_IRQFLAGS1_RXREADY          = 0x40  # Set in Rx mode, after RSSI, AGC and AFC. Cleared when leaving Rx.
RF_IRQFLAGS1_TXREADY          = 0x20  # Set in Tx mode, after PA ramp-up. Cleared when leaving Tx.
RF_IRQFLAGS1_PLLLOCK          = 0x10  # Set (in FS, RX, or TX) when the PLL is locked. Cleared when it is not.
RF_IRQFLAGS1_RSSI             = 0x08  # Set in Rx when the RssiValue exceeds RssiThreshold. Cleared when leaving Rx.
RF_IRQFLAGS1_TIMEOUT          = 0x04  # Set when a timeout occurs. Cleared when leaving Rx or FIFO is emptied.
RF_IRQFLAGS1_AUTOMODE         = 0x02  # Set when entering Intermediate mode. Cleared when exiting Intermediate mode.
RF_IRQFLAGS1_SYNCADDRESSMATCH = 0x01  # Set when Sync and Address (if enabled) are detected. Cleared when leaving Rx or FIFO is emptied.

# RegIrqFlags2 (0x28)
RF_IRQFLAGS2_FIFOFULL     = 0x80  # Set when FIFO is full (contains 66 bytes), else cleared.
RF_IRQFLAGS2_FIFONOTEMPTY = 0x40  # Set when FIFo contains at least one byte, else cleared.
RF_IRQFLAGS2_FIFOLEVEL    = 0x20  # Set when the number of bytes in the FIFO strictly exceeds FifoThreshold, else cleared.
RF_IRQFLAGS2_FIFOOVERRUN  = 0x10  # Set when FIFO overrun occurs (except in Sleep mode). Flags and FIFO are cleared when this bit is set.
RF_IRQFLAGS2_PACKETSENT   = 0x08  # Set in Tx when the complete packet has been setn. Cleared when exiting Tx.
RF_IRQFLAGS2_PAYLOADREADY = 0x04  # Set in Rx when the payload is ready. Cleared when FIFO is empty.
RF_IRQFLAGS2_CRCOK        = 0x02  # Set in Rx when the CRC of the payload is Ok. Cleared when FIFO is empty.
RF_IRQFLAGS2_LOWBAT       = 0x01

# RegRssiThresh (0x29) - RSSI trigger level for Rssi interrupt - RssiThreshold / 2 [dBm]
RF_RSSITHRESH_VALUE = 0xE4  # Default

# RegRxTimeout1 (0x2A) - Timeout interrupt TimeoutRxStart*16*T_bit after switching to Rx mode if Rssi interrupt doesn't occur
RF_RXTIMEOUT1_RXSTART_VALUE = 0x00  # Default

# RegRxTimeout2 (0x2B) - Timeout interrupt is generated TimeoutRssiThresh*16*T_bit after Rssi interrupt if PayloadReady interrupt doesn't occur
RF_RXTIMEOUT2_RSSITHRESH_VALUE = 0x00  # Default

# RegPreamble (0x2C, 0x2D) - Size of the preamble to be sent
RF_PREAMBLESIZE_MSB_VALUE = 0x00  # Default
RF_PREAMBLESIZE_LSB_VALUE = 0x03  # Default


# RegSyncConfig (0x2E)
# Enables the Sync word generation and detection
RF_SYNC_ON  = 0x80  # Default
RF_SYNC_OFF = 0x00

# FIFO filling condition
RF_SYNC_FIFOFILL_AUTO   = 0x00  # Default: If SyncAddress interrupt occurs
RF_SYNC_FIFOFILL_MANUAL = 0x40  # as long as FifoFillCondition is set

# Size of the Sync word: (SyncSize + 1) bytes
RF_SYNC_SIZE_1 = 0x00
RF_SYNC_SIZE_2 = 0x08
RF_SYNC_SIZE_3 = 0x10
RF_SYNC_SIZE_4 = 0x18  # Default
RF_SYNC_SIZE_5 = 0x20
RF_SYNC_SIZE_6 = 0x28
RF_SYNC_SIZE_7 = 0x30
RF_SYNC_SIZE_8 = 0x38

# Number of tolerated bit errors in Sync word
RF_SYNC_TOL_0 = 0x00  # Default
RF_SYNC_TOL_1 = 0x01
RF_SYNC_TOL_2 = 0x02
RF_SYNC_TOL_3 = 0x03
RF_SYNC_TOL_4 = 0x04
RF_SYNC_TOL_5 = 0x05
RF_SYNC_TOL_6 = 0x06
RF_SYNC_TOL_7 = 0x07


# RegSyncValue[1-8] (0x2F-0x36) - Used if SyncOn is set
RF_SYNC_BYTE1_VALUE = 0x00  # Default
RF_SYNC_BYTE2_VALUE = 0x00  # Default
RF_SYNC_BYTE3_VALUE = 0x00  # Default
RF_SYNC_BYTE4_VALUE = 0x00  # Default
RF_SYNC_BYTE5_VALUE = 0x00  # Default
RF_SYNC_BYTE6_VALUE = 0x00  # Default
RF_SYNC_BYTE7_VALUE = 0x00  # Default
RF_SYNC_BYTE8_VALUE = 0x00  # Default


# RegPacketConfig1 (0x37)
# Defines the packet format used
RF_PACKET1_FORMAT_FIXED    = 0x00  # Default
RF_PACKET1_FORMAT_VARIABLE = 0x80

# Defines DC-free encoding/decoding performed
RF_PACKET1_DCFREE_OFF        = 0x00  # Default: None (Off)
RF_PACKET1_DCFREE_MANCHESTER = 0x20  # Manchester
RF_PACKET1_DCFREE_WHITENING  = 0x40  # Whitening

# Enables CRC calculation/check (Tx/Rx)
RF_PACKET1_CRC_ON  = 0x10  # Default: On
RF_PACKET1_CRC_OFF = 0x00  # Off

# Defines the behavior of the packet handler when CRC check fails
RF_PACKET1_CRCAUTOCLEAR_ON  = 0x00  # Default: Clear FIFO and restart new packet reception. No PayloadReady interrupt issued.
RF_PACKET1_CRCAUTOCLEAR_OFF = 0x08  # Do not clear FIFO. PayloadReady interrupt issued.

# Defines address based filtering in Rx
RF_PACKET1_ADRSFILTERING_OFF  = 0x00  # Default: None (Off)
RF_PACKET1_ADRSFILTERING_NODE = 0x02  # Address field must match NodeAddress
RF_PACKET1_ADRSFILTERING_NODEBROADCAST = 0x04  # Address field must match NodeAddress or BroadcastAddress


# RegPayloadLength (0x38) - Fixed PacketFormat: Payload length, Variable # PacketFormat: Max length in Rx
RF_PAYLOADLENGTH_VALUE = 0x40  # Default

# RegBroadcastAdrs (0x3A) - Broadcast address used in address filtering
RF_BROADCASTADDRESS_VALUE = 0x00 # Default


# RegAutoModes (0x3B)
# Interrupt condition for entering the intermediate mode
RF_AUTOMODES_ENTER_OFF           = 0x00  # Default: None (AutoModes Off)
RF_AUTOMODES_ENTER_FIFONOTEMPTY  = 0x20  # Rising edge of FifoNotEmpty
RF_AUTOMODES_ENTER_FIFOLEVEL     = 0x40  # Rising edge of FifoLevel
RF_AUTOMODES_ENTER_CRCOK         = 0x60  # Rising edge of CrcOk
RF_AUTOMODES_ENTER_PAYLOADREADY  = 0x80  # Rising edge of PayloadReady
RF_AUTOMODES_ENTER_SYNCADRSMATCH = 0xA0  # Rising edge of SyncAddress
RF_AUTOMODES_ENTER_PACKETSENT    = 0xC0  # Rising edge of PacketSent
RF_AUTOMODES_ENTER_FIFOEMPTY     = 0xE0  # Falling edge of FifoNotEmpty

# Interrupt condition for exiting the intermediate mode
RF_AUTOMODES_EXIT_OFF           = 0x00  # Default: None (AutoModes Off)
RF_AUTOMODES_EXIT_FIFOEMPTY     = 0x04  # Falling edge of FifoNotEmpty
RF_AUTOMODES_EXIT_FIFOLEVEL     = 0x08  # Rising edge of FifoLevel or Timeout
RF_AUTOMODES_EXIT_CRCOK         = 0x0C  # Rising edge of CrcOk or Timeout
RF_AUTOMODES_EXIT_PAYLOADREADY  = 0x10  # Rising edge of PayloadReady or Timeout
RF_AUTOMODES_EXIT_SYNCADRSMATCH = 0x14  # Rising edge of SyncAddress or Timeout
RF_AUTOMODES_EXIT_PACKETSENT    = 0x18  # Rising edge of PacketSent
RF_AUTOMODES_EXIT_RXTIMEOUT     = 0x1C  # Rising edge of Timeout

# Intermediate mode
RF_AUTOMODES_INTERMEDIATE_SLEEP       = 0x00  # Default: Sleep mode (SLEEP)
RF_AUTOMODES_INTERMEDIATE_STANDBY     = 0x01  # Standby mode (STDBY)
RF_AUTOMODES_INTERMEDIATE_RECEIVER    = 0x02  # Receiver mode (RX)
RF_AUTOMODES_INTERMEDIATE_TRANSMITTER = 0x03  # Transmitter mode (TX)


# RegFifoThresh (0x3C)
# Defines the condition to start packet transmission
RF_FIFOTHRESH_TXSTART_FIFOTHRESH   = 0x00  # FifoLevel (i.e. the number of bytes in the FIFO exceeds FifoThreshold)
RF_FIFOTHRESH_TXSTART_FIFONOTEMPTY = 0x80  # Default: FifoNotEmpty (i.e. at least one byte in the FIFO)

# Used to trigger FifoLevel interrupt
RF_FIFOTHRESH_VALUE = 0x0F  # Default


# RegPacketConfig2 (0x3D)
# After PayloadReady occured, defines the delay between FIFO empty and the start of a new RSSI phase for next packet. Must match the transmitter's PA ramp-down time.
RF_PACKET2_RXRESTARTDELAY_1BIT     = 0x00  # Default
RF_PACKET2_RXRESTARTDELAY_2BITS    = 0x10
RF_PACKET2_RXRESTARTDELAY_4BITS    = 0x20
RF_PACKET2_RXRESTARTDELAY_8BITS    = 0x30
RF_PACKET2_RXRESTARTDELAY_16BITS   = 0x40
RF_PACKET2_RXRESTARTDELAY_32BITS   = 0x50
RF_PACKET2_RXRESTARTDELAY_64BITS   = 0x60
RF_PACKET2_RXRESTARTDELAY_128BITS  = 0x70
RF_PACKET2_RXRESTARTDELAY_256BITS  = 0x80
RF_PACKET2_RXRESTARTDELAY_512BITS  = 0x90
RF_PACKET2_RXRESTARTDELAY_1024BITS = 0xA0
RF_PACKET2_RXRESTARTDELAY_2048BITS = 0xB0
RF_PACKET2_RXRESTARTDELAY_NONE     = 0xC0

RF_PACKET2_RXRESTART = 0x04  # Forces the Receiver in WAIT mode, in Continuous Rx mode. Always reads 0.

# Enables automatic Rx restart (RSSI phase) after PayloadReady occurred and packet has been completely read from FIFO
RF_PACKET2_AUTORXRESTART_ON = 0x02  # Default: Rx automatically restarted after InterPacketRxDelay
RF_PACKET2_AUTORXRESTART_OFF = 0x00  # RestartRx can be used.

# Enable the AES encryption/decryption
RF_PACKET2_AES_ON  = 0x01
RF_PACKET2_AES_OFF = 0x00  # Default


# RegAesKey[1-16] (0x3E-0x4D) - Bytes of cipher key
RF_AESKEY1_VALUE  = 0x00  # Default
RF_AESKEY2_VALUE  = 0x00  # Default
RF_AESKEY3_VALUE  = 0x00  # Default
RF_AESKEY4_VALUE  = 0x00  # Default
RF_AESKEY5_VALUE  = 0x00  # Default
RF_AESKEY6_VALUE  = 0x00  # Default
RF_AESKEY7_VALUE  = 0x00  # Default
RF_AESKEY8_VALUE  = 0x00  # Default
RF_AESKEY9_VALUE  = 0x00  # Default
RF_AESKEY10_VALUE = 0x00  # Default
RF_AESKEY11_VALUE = 0x00  # Default
RF_AESKEY12_VALUE = 0x00  # Default
RF_AESKEY13_VALUE = 0x00  # Default
RF_AESKEY14_VALUE = 0x00  # Default
RF_AESKEY15_VALUE = 0x00  # Default
RF_AESKEY16_VALUE = 0x00  # Default


# RegTemp1 (0x4E)
RF_TEMP1_MEAS_START      = 0x08  # Triggers the temperature measurement when set. Always reads 0.
RF_TEMP1_MEAS_RUNNING    = 0x04  # Set to 1 while the temperature measurement is running. Toggles back to 0 when the measurement has completed. The received cannot be used while measuring temperature.
RF_TEMP1_ADCLOWPOWER_ON  = 0x01  # Default
RF_TEMP1_ADCLOWPOWER_OFF = 0x00

# RegTestDagc (0x6F) - Fading Margin Improvement
RF_DAGC_NORMAL            = 0x00  # Normal mode
RF_DAGC_IMPROVED_LOWBETA1 = 0x20  # Improved margin, use if AfcLowBetaOn = 1.
RF_DAGC_IMPROVED_LOWBETA0 = 0x30  # Default: Improved margin, use if AfcLowBetaOn = 0.

# Settings pulled from RFM69.h
RF69_315MHZ = 31  # Non trivial values to avoid misconfiguration.
RF69_433MHZ = 43
RF69_868MHZ = 86
RF69_915MHZ = 91
RF69_FRFMSB = {RF69_315MHZ: RF_FRFMSB_315, RF69_433MHZ: RF_FRFMSB_433,
               RF69_868MHZ: RF_FRFMSB_868, RF69_915MHZ: RF_FRFMSB_915}
RF69_FRFMID = {RF69_315MHZ: RF_FRFMID_315, RF69_433MHZ: RF_FRFMID_433,
               RF69_868MHZ: RF_FRFMID_868, RF69_915MHZ: RF_FRFMID_915}
RF69_FRFLSB = {RF69_315MHZ: RF_FRFLSB_315, RF69_433MHZ: RF_FRFLSB_433,
               RF69_868MHZ: RF_FRFLSB_868, RF69_915MHZ: RF_FRFLSB_915}


RF69_MAX_DATA_LEN = 60  # To take advantage of the built in AES/CRC we want to limit the frame size to the internal FIFO size (66 bytes - 4 bytes overhead).

CSMA_LIMIT        = -90  # Upper RX signal sensitivity threshold in dBm for carrier sense access.
RF69_MODE_SLEEP   = 0  # XTAL OFF
RF69_MODE_STANDBY = 1  # XTAL ON
RF69_MODE_SYNTH   = 2  # PLL ON
RF69_MODE_RX      = 3  # RX MODE
RF69_MODE_TX      = 4  # TX MODE
RF69_OPMODES      = {
    RF69_MODE_SLEEP:   RF_OPMODE_SLEEP,
    RF69_MODE_STANDBY: RF_OPMODE_STANDBY,
    RF69_MODE_SYNTH:   RF_OPMODE_SYNTHESIZER,
    RF69_MODE_RX:      RF_OPMODE_RECEIVER,
    RF69_MODE_TX:      RF_OPMODE_TRANSMITTER
}

COURSE_TEMP_COEF    = -90  # Puts the temperature reading in the ballpark, user can fine tune the returned value.
RF69_BROADCAST_ADDR = 255
RF69_CSMA_LIMIT_S   = 1
RF69_TX_LIMIT_S     = 1
RFM69_CTL_SENDACK   = 0x80
RFM69_CTL_REQACK    = 0x40

powerLevel = 31
