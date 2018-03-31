import logging

import voluptuous as vol

# Import the device class from the component that you want to support
from homeassistant.components.binary_sensor import BinarySensorDevice, PLATFORM_SCHEMA
from homeassistant.const import CONF_NAME
import homeassistant.helpers.config_validation as cv
import homeassistant.loader as loader

DEPENDENCIES = ['rfm69']

_LOGGER = logging.getLogger(__name__)

CONF_NODE_ID = 'node_id'

# Validation of the user's configuration
PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_NODE_ID): cv.positive_int,
    vol.Required(CONF_NAME): cv.string,
})


def setup_platform(hass, config, add_devices, discovery_info=None):
    """Setup the Rfm69 switch platform."""
    rfm69 = loader.get_component('rfm69')

    # Verify that Rfm69 chip is present
    if rfm69.RADIO is None:
        _LOGGER.error("A connection has not been made to the Rfm69 chip")
        return

    node_id = config[CONF_NODE_ID]
    name    = config[CONF_NAME]

    add_devices([ButtonRemote(rfm69.RADIO, name, node_id)])


class ButtonRemote(BinarySensorDevice):
    """Representation of an Arduino button remote."""

    def __init__(self, rfm69, name, node_id):
        """Initialize the switch."""
        import threading

        self._rfm69 = rfm69
        self._name = name
        self._node_id = node_id
        self._state = False
        self._rfm69.add_device(node_id)

        self._thread_listen = threading.Thread(target=self._listen, daemon=True)
        self._thread_listen.start()

    @property
    def name(self):
        """Return the display name of the button."""
        return self._name

    @property
    def should_poll(self):
        """No polling needed."""
        return True

    @property
    def is_on(self):
        """Return true if sensor is on."""
        return self._state

    def _listen(self):
        while True:
            response = self._rfm69.receive_message(self._node_id, time_wait_sec=None)
            if response is None:
                _LOGGER.warning("ButtonRemote: Response is None???")
            else:
                _LOGGER.warning("ButtonRemote: Response '{0}', switching to {1}.".format(response, not self._state))
                self._state = not self._state

