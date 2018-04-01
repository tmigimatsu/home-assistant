import logging

import voluptuous as vol

# Import the device class from the component that you want to support
from homeassistant.components.switch import SwitchDevice, PLATFORM_SCHEMA
from homeassistant.const import CONF_NAME, CONF_TIMEOUT
import homeassistant.helpers.config_validation as cv
import homeassistant.loader as loader

DEPENDENCIES = ['rfm69']

_LOGGER = logging.getLogger(__name__)

CONF_NODE_ID = 'node_id'
CONF_SWITCHES = 'switches'
CONF_PIN = 'pin'

# Validation of the user's configuration
PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_NODE_ID): cv.positive_int,
    vol.Required(CONF_SWITCHES): vol.Schema([
        vol.Schema({
            vol.Required(CONF_PIN): cv.positive_int,
            vol.Required(CONF_NAME): cv.string,
            vol.Required(CONF_TIMEOUT): cv.positive_int
        })
    ])
})


def setup_platform(hass, config, add_devices, discovery_info=None):
    """Setup the Rfm69 switch platform."""
    rfm69 = loader.get_component('rfm69')

    # Verify that Rfm69 chip is present
    if rfm69.RADIO is None:
        _LOGGER.error("A connection has not been made to the Rfm69 chip")
        return

    node_id = config[CONF_NODE_ID]
    switches = config[CONF_SWITCHES]

    devices = []
    for switch in switches:
        pin     = switch[CONF_PIN]
        name    = switch[CONF_NAME]
        timeout = switch[CONF_TIMEOUT]
        devices.append(MultiChannelRelay(rfm69.RADIO, name, node_id, pin, timeout))
    add_devices(devices)


class MultiChannelRelay(SwitchDevice):
    """Representation of a multichannel Arduino relay."""

    def __init__(self, rfm69, name, node_id, relay_pin, timeout_ms):
        """Initialize the switch."""
        self._rfm69 = rfm69
        self._name = name
        self._node_id = node_id
        self._relay_pin = relay_pin
        self._timeout = timeout_ms
        self._cache = True
        self._state = None
        self._available = True
        self._rfm69.add_device(node_id)

    @property
    def name(self):
        """Return the display name of the switch."""
        return self._name

    @property
    def available(self):
        """Return if the switch is available."""
        return self._available

    @property
    def is_on(self):
        """Return true if switch is on."""
        return self._state

    def turn_on(self, **kwargs):
        """Turn the switch on."""
        status = self._rfm69.send_message(self._node_id, "S.%d.1.%d." % (self._relay_pin, self._timeout))
        if status is None:
            _LOGGER.warning("MultiChannelRelay.turn_on(): Could not turn %s on.", self._name)
            self._available = False
            return

        self._state = chr(status[self._relay_pin]) == '1'
        self._available = True
        self._cache = False

    def turn_off(self, **kwargs):
        """Turn the switch off."""
        status = self._rfm69.send_message(self._node_id, "S.%d.0." % (self._relay_pin))
        if status is None:
            _LOGGER.warning("MultiChannelRelay.turn_off(): Could not turn %s off.", self._name)
            self._available = False
            return

        self._state = chr(status[self._relay_pin]) == '1'
        self._available = True
        self._cache = False

    def update(self):
        """Fetch new state data for the switch."""
        status = self._rfm69.send_message(self._node_id, "G.", cache=self._cache)
        if status is None:
            _LOGGER.warning("MultiChannelRelay.update(): Could not read state for %s.", self._name)
            self._available = False
            return

        self._state = chr(status[self._relay_pin]) == '1'
        self._available = True
        self._cache = True

