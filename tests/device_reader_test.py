import asyncio
import time
import unittest

from bleak.exc import BleakCharacteristicNotFoundError, BleakError

from bluetti_bt_lib.base_devices import BaseDeviceV1
from bluetti_bt_lib import DeviceReader, DeviceReaderConfig
from bluetti_bt_lib.bluetooth.encryption import (
    KEX_MAGIC,
    BluettiEncryption,
    Message,
    hexsum,
)
from bluetti_bt_lib.fields import FieldName
from bluetti_bt_lib.utils.bleak_client_mock import ClientMockNoEncryption

CHALLENGE_BODY = bytes.fromhex("0104") + bytes.fromhex("11223344")
CHALLENGE = KEX_MAGIC + CHALLENGE_BODY + hexsum(CHALLENGE_BODY, 2)


class ClientMockHandshakeWriteFails(ClientMockNoEncryption):
    """Sends a challenge like a real device, then fails the response write."""

    async def start_notify(self, char_specifier, callback, **kwargs):
        # Bleak delivers notifications from its own task
        asyncio.get_running_loop().create_task(callback(0, bytearray(CHALLENGE)))

    async def write_gatt_char(self, char_specifier, data, response=None):
        raise BleakError("GATT Protocol Error: Unlikely Error")


class ClientMockNotifyFails(ClientMockNoEncryption):
    """Drops the connection while subscribing to notifications."""

    async def start_notify(self, char_specifier, callback, **kwargs):
        raise BleakError("Bluetooth GATT Error handle=32 error=133")


class ClientMockStaleServices(ClientMockNoEncryption):
    """Fails writes as if the cached GATT services were out of date."""

    def __init__(self):
        super().__init__()
        self.cache_cleared = False

    async def write_gatt_char(self, char_specifier, data, response=None):
        raise BleakCharacteristicNotFoundError(char_specifier)

    async def clear_cache(self):
        self.cache_cleared = True
        return True


class TestDeviceReader(unittest.IsolatedAsyncioTestCase):
    def __init__(self, methodName="runTest"):
        super().__init__(methodName)
        self.ble_mock = ClientMockNoEncryption()

        # Device type
        self.ble_mock.add_r_str(10, "AC300", 6)
        # Serial
        self.ble_mock.add_r_sn(17, 2300000000000)
        # DC input power
        self.ble_mock.add_r_int(36, 10)
        # AC input power
        self.ble_mock.add_r_int(37, 8)
        # AC output power
        self.ble_mock.add_r_int(38, 9)
        # AC output power
        self.ble_mock.add_r_int(39, 7)
        # SOC
        self.ble_mock.add_r_int(43, 78)

    async def test_read_all_correct(self):
        device = BaseDeviceV1()
        reader = DeviceReader(
            "00:11:00:11:00:11",
            device,
            asyncio.Future,
            ble_client=self.ble_mock,
        )

        data = await reader.read()

        self.assertEqual(data.get(FieldName.DEVICE_TYPE.value), "AC300")
        self.assertEqual(data.get(FieldName.DEVICE_SN.value), 2300000000000)
        self.assertEqual(data.get(FieldName.DC_INPUT_POWER.value), 10)
        self.assertEqual(data.get(FieldName.AC_INPUT_POWER.value), 8)
        self.assertEqual(data.get(FieldName.AC_OUTPUT_POWER.value), 9)
        self.assertEqual(data.get(FieldName.DC_OUTPUT_POWER.value), 7)
        self.assertEqual(data.get(FieldName.BATTERY_SOC.value), 78)

    async def test_read_soc_wrong(self):
        # SOC
        self.ble_mock.add_r_int(43, 1234)

        device = BaseDeviceV1()
        reader = DeviceReader(
            "00:11:00:11:00:11",
            device,
            asyncio.Future,
            ble_client=self.ble_mock,
        )

        data = await reader.read()

        self.assertIsNone(data.get(FieldName.BATTERY_SOC.value))

    async def test_invalid_encrypted_notification_is_ignored(self):
        device = BaseDeviceV1()
        reader = DeviceReader(
            "00:11:00:11:00:11",
            device,
            asyncio.Future,
            DeviceReaderConfig(use_encryption=True),
            ble_client=self.ble_mock,
        )
        reader.encryption.unsecure_aes_key = bytes(16)
        reader.encryption.unsecure_aes_iv = bytes(16)
        reader.notify_future = asyncio.Future()

        await reader._notification_handler(0, bytearray(b"\x00\x01abcde"))

        self.assertFalse(reader.notify_future.done())

    async def test_handshake_write_failure_aborts_read(self):
        reader = DeviceReader(
            "00:11:00:11:00:11",
            BaseDeviceV1(),
            asyncio.Future,
            DeviceReaderConfig(timeout=10, use_encryption=True),
            ble_client=ClientMockHandshakeWriteFails(),
        )

        start = time.monotonic()
        data = await reader.read()

        self.assertIsNone(data)
        self.assertIn("Unlikely Error", reader.last_error)
        # Fails as soon as the write fails instead of waiting for the timeout
        self.assertLess(time.monotonic() - start, 2)

    async def test_failed_read_resets_encryption(self):
        reader = DeviceReader(
            "00:11:00:11:00:11",
            BaseDeviceV1(),
            asyncio.Future,
            DeviceReaderConfig(timeout=10, use_encryption=True),
            ble_client=ClientMockNotifyFails(),
        )
        # Left over from an earlier session
        reader.encryption.secure_aes_key = bytes(32)
        reader.encryption.peer_pubkey = bytes(64)
        reader.encryption.unsecure_aes_key = None

        self.assertTrue(reader.encryption.is_ready_for_commands)

        data = await reader.read()

        self.assertIsNone(data)
        self.assertFalse(reader.encryption.is_ready_for_commands)

    async def test_stale_services_clear_cache(self):
        client = ClientMockStaleServices()
        reader = DeviceReader(
            "00:11:00:11:00:11",
            BaseDeviceV1(),
            asyncio.Future,
            ble_client=client,
        )

        data = await reader.read()

        self.assertIsNone(data)
        self.assertIn("was not found", reader.last_error)
        self.assertTrue(client.cache_cleared)

    async def test_failures_are_not_logged_as_warnings(self):
        reader = DeviceReader(
            "00:11:00:11:00:11",
            BaseDeviceV1(),
            asyncio.Future,
            DeviceReaderConfig(timeout=10, use_encryption=True),
            ble_client=ClientMockHandshakeWriteFails(),
        )

        with self.assertNoLogs("bluetti_bt_lib", level="WARNING"):
            await reader.read()

    def test_session_keys_are_not_logged_at_info(self):
        with self.assertNoLogs("bluetti_bt_lib.bluetooth.encryption", level="INFO"):
            BluettiEncryption().msg_challenge(Message(CHALLENGE))
