"""Platform for Nice Gate integration."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

# Import the device class from the component that you want to support
from homeassistant.components.cover import CoverDeviceClass, CoverEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_CLOSED, STATE_CLOSING, STATE_OPEN, STATE_OPENING
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import DOMAIN
from .nice_api import NiceGateApi

_LOGGER = logging.getLogger("nicegate")

STATES_MAP = {
    "closed": STATE_CLOSED,
    "closing": STATE_CLOSING,
    "open": STATE_OPEN,
    "opening": STATE_OPENING,
}


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up the Nice gate cover."""
    api = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([NiceGate(hass, api, entry.data["mac"])])


class NiceGate(CoordinatorEntity, CoverEntity):
    """Representation of an Nice Gate."""

    _attr_device_class = CoverDeviceClass.GATE.value
    _attr_name = "Nice gate"

    def __init__(self, hass, api: NiceGateApi, device_id) -> None:
        """Initialize an NiceGate."""
        self._device_id = device_id
        self.api = api
        super().__init__(DataUpdateCoordinator(hass, _LOGGER, name="Nice Gate"))
        self._state: str | None = None
        self._state_before_move: str | None = None
        self.api.set_update_callback(self.update_status)
        asyncio.create_task(self.api.status())

    @property
    def is_closed(self) -> bool | None:
        """Return if the cover is closed."""
        if self._state is None:
            return None
        return self._state == STATE_CLOSED

    @property
    def is_closing(self) -> bool | None:
        """Return if the cover is closing."""
        if self._state is None:
            return None
        return self._state == STATE_CLOSING

    @property
    def is_opening(self) -> bool | None:
        """Return if the cover is opening."""
        if self._state is None:
            return None
        return self._state == STATE_OPENING

    async def async_close_cover(self, **kwargs: Any) -> None:
        """Close the cover."""
        if self._state in [STATE_CLOSED, STATE_CLOSING]:
            return
        self._state_before_move = self._state
        self._state = STATE_CLOSING
        await self.api.change("close")

    async def async_open_cover(self, **kwargs: Any) -> None:
        """Open the cover."""
        if self._state in [STATE_OPEN, STATE_OPENING]:
            return
        self._state_before_move = self._state
        self._state = STATE_OPENING
        await self.api.change("open")

    async def async_stop_cover(self, **kwargs: Any) -> None:
        """Open the cover."""
        if self._state in [STATE_OPEN, STATE_CLOSED]:
            return
        await self.api.change("stop")

    async def update_status(self) -> None:
        """Update the state and attributes."""
        _LOGGER.info("Updated")
        status = await self.api.get_status()
        self._state = STATES_MAP.get(status)
        self.coordinator.async_set_updated_data(None)
