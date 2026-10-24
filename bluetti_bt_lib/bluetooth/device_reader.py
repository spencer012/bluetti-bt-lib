import asyncio
import logging
import async_timeout
from typing import Any, Callable, List, cast
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakCharacteristicNotFoundError, BleakError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from .encryption import BluettiEncryption, Message, MessageType
from ..base_devices import BluettiDevice
from ..const import NOTIFY_UUID, WRITE_UUID
from ..registers import ReadableRegisters, DeviceRegister
from ..utils.privacy import mac_loggable


class DeviceReaderConfig:
    def __init__(self, timeout: int = 60, use_encryption: bool = False):
        self.timeout = timeout
        self.use_encryption = use_encryption


class DeviceReader:
    def __init__(
        self,
        mac: str,
        bluetti_device: BluettiDevice,
        future_builder_method: Callable[[], asyncio.Future[Any]],
        config: DeviceReaderConfig = DeviceReaderConfig(),
        lock: asyncio.Lock = asyncio.Lock(),
        ble_client: BleakClient | None = None,
    ):
        self.mac = mac
        self.bluetti_device = bluetti_device
        self.create_future = future_builder_method
        self.config = config
        self.polling_lock = lock

        self.ble_client = ble_client
        """Used for unittests"""

        self.logger = logging.getLogger(
            f"{__name__}.{mac_loggable(mac).replace(':', '_')}"
        )

        self.device = None
        self.client = None

        self.has_notifier = False
        self.current_registers = None
        self.notify_response = bytearray()
        self.notify_future: asyncio.Future[Any] | None = None
        self.encryption = BluettiEncryption()

        self.last_error: str | None = None
        """Why the last read returned None, if it did"""

        self._notification_error: Exception | None = None

    async def read(
        self, only_registers: List[ReadableRegisters] | None = None, raw: bool = False
    ) -> dict | None:

        registers = self.bluetti_device.get_polling_registers()
        pack_registers = self.bluetti_device.get_pack_polling_registers()

        if only_registers is not None:
            registers = only_registers
            pack_registers = []

        parsed_data: dict = {}

        self.logger.debug("Reading device registers")

        async with self.polling_lock:
            self.last_error = None
            self._notification_error = None

            try:
                async with async_timeout.timeout(self.config.timeout):
                    self.logger.debug("Searching for device")

                    if self.ble_client:
                        self.device = None
                    else:
                        self.device = await BleakScanner.find_device_by_address(
                            self.mac, timeout=5
                        )

                        if self.device is None:
                            self._set_error("Device not found")
                            return None

                    self.logger.debug("Connecting to device")

                    if self.ble_client:
                        self.client = self.ble_client
                    else:
                        self.client = await establish_connection(
                            BleakClientWithServiceCache,
                            self.device,
                            self.device.name or "Unknown Device",
                            max_attempts=10,
                        )

                    self.logger.debug("Connected to device")

                    if not self.has_notifier:
                        await self.client.start_notify(
                            NOTIFY_UUID, self._notification_handler
                        )
                        self.has_notifier = True

                    self.logger.debug("Notification handler setup complete")

                    if self.config.use_encryption:
                        self.logger.debug("Waiting for encryption handshake")

                    while (
                        self.config.use_encryption
                        and not self.encryption.is_ready_for_commands
                    ):
                        if self._notification_error is not None:
                            raise self._notification_error
                        await asyncio.sleep(0.1)

                    for register in registers:
                        body = register.parse_response(
                            await self._async_send_command(register)
                        )

                        self.logger.debug("Raw data: %s", body)

                        if raw:
                            d = {}
                            d[register.starting_address] = body
                            parsed_data.update(d)
                            continue

                        parsed = self.bluetti_device.parse(
                            register.starting_address, body
                        )

                        self.logger.debug("Parsed data: %s", parsed)

                        parsed_data.update(parsed)

                    for pack in range(1, self.bluetti_device.max_packs + 1):
                        body = register.parse_response(
                            await self._async_send_command(
                                self.bluetti_device.get_pack_selector(pack),
                            )
                        )

                        # We need to wait for the powerstation to populate all registers
                        await asyncio.sleep(3)

                        for register in pack_registers:
                            body = register.parse_response(
                                await self._async_send_command(register)
                            )

                            self.logger.debug("Raw data: %s", body)

                            if raw:
                                d = {}
                                d[register.starting_address] = body
                                parsed_data.update(d)
                                continue

                            parsed = self.bluetti_device.parse(
                                register.starting_address,
                                body,
                                pack_num=pack,
                            )

                            self.logger.debug("Parsed data: %s", parsed)

                            parsed_data.update(parsed)

            except TimeoutError:
                self._set_error("Timeout")
                return None
            except BleakCharacteristicNotFoundError as err:
                # The cached GATT services are stale; rediscover them next time
                self._set_error(f"Bleak error: {err}")
                await self._clear_service_cache()
                return None
            except BleakError as err:
                self._set_error(f"Bleak error: {err}")
                return None
            except Exception as err:
                self._set_error(f"Unknown error: {err!r}")
                return None
            finally:
                if self.has_notifier:
                    try:
                        await self.client.stop_notify(NOTIFY_UUID)
                        self.logger.debug("Stopped notifier")
                    except Exception:
                        # Ignore errors here
                        pass
                    self.has_notifier = False
                if self.client:
                    try:
                        await self.client.disconnect()
                        self.logger.debug("Disconnected from device")
                    except Exception as err:
                        self.logger.debug("Error while disconnecting: %s", err)

                # Reset encryption keys, also after a failed read. Otherwise the
                # next read skips the handshake and uses the old session key.
                self.encryption.reset()

            # Check if dict is empty
            if not parsed_data:
                self._set_error("No data received")
                return None

            return parsed_data

    def _set_error(self, error: str):
        """Record why the read failed.

        Logged at debug only: single failed polls are common over BLE, so
        callers decide when a failure is worth reporting (see last_error).
        """
        self.last_error = error
        self.logger.debug("Read failed: %s", error)

    async def _clear_service_cache(self):
        clear_cache = getattr(self.client, "clear_cache", None)
        if clear_cache is None:
            return
        try:
            await clear_cache()
            self.logger.debug("Cleared GATT service cache")
        except Exception as err:
            self.logger.debug("Failed to clear GATT service cache: %s", err)

    async def _async_send_command(self, registers: DeviceRegister) -> bytes:
        """Send command and return response"""
        self.current_registers = registers
        self.notify_response = bytearray()
        self.notify_future = self.create_future()

        command_bytes = bytes(registers)

        # Encrypt command
        if self.config.use_encryption is True:
            if not self.encryption.is_ready_for_commands:
                return bytes()
            command_bytes = self.encryption.aes_encrypt(
                command_bytes, self.encryption.secure_aes_key, None
            )

        try:
            # Make request
            await self.client.write_gatt_char(WRITE_UUID, command_bytes)

            self.logger.debug("Request sent (%s)", registers)

            # Wait for response
            res = await asyncio.wait_for(self.notify_future, timeout=5)

            self.logger.debug("Got response")

            return cast(bytes, res)
        except asyncio.TimeoutError:
            self.logger.debug("No response for %s", registers)

        return bytes()

    async def _notification_handler(self, _: int, data: bytearray):
        """Handle bt data.

        Bleak runs this callback as a task, so an exception raised here would
        only be logged as "Task exception was never retrieved". Keep it for
        read() instead, which aborts a pending handshake with it.
        """
        try:
            await self._handle_notification(data)
        except Exception as err:
            self.logger.debug("Error handling notification: %s", err)
            self._notification_error = err

    async def _handle_notification(self, data: bytearray):
        self.logger.debug("Got new data")

        if self.config.use_encryption is True:
            message = Message(data)

            if message.is_pre_key_exchange:
                message.verify_checksum()

                if message.type == MessageType.CHALLENGE:
                    challenge_response = self.encryption.msg_challenge(message)
                    await self.client.write_gatt_char(WRITE_UUID, challenge_response)
                    return

                if message.type == MessageType.CHALLENGE_ACCEPTED:
                    self.logger.debug("Challenge accepted")
                    return

            if self.encryption.unsecure_aes_key is None:
                self.logger.debug(
                    "Ignoring encrypted message received before key initialization"
                )
                return

            key, iv = self.encryption.getKeyIv()
            try:
                decrypted = Message(self.encryption.aes_decrypt(message.buffer, key, iv))
            except ValueError as err:
                self.logger.debug("Ignoring invalid encrypted notification: %s", err)
                return

            if decrypted.is_pre_key_exchange:
                decrypted.verify_checksum()

                if decrypted.type == MessageType.PEER_PUBKEY:
                    peer_pubkey_response = self.encryption.msg_peer_pubkey(decrypted)
                    await self.client.write_gatt_char(WRITE_UUID, peer_pubkey_response)
                    return

                if decrypted.type == MessageType.PUBKEY_ACCEPTED:
                    self.encryption.msg_key_accepted(decrypted)
                    return

            # Handle as message
            data = decrypted.buffer

        # Save data
        self.notify_response.extend(data)

        if self.notify_future is None:
            return

        if self.notify_future.done():
            return

        self.notify_future.set_result(self.notify_response)
