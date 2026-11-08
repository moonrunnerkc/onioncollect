import asyncio
import unittest
from unittest import mock

from stem import Signal

from onioncollect import tor_pool
from onioncollect.tor_pool import TorInstance, TorPool
from tests.fixtures import throwaway_settings


def fake_controller(ready="1", newnym_available=True, newnym_wait=0.0):
    controller = mock.MagicMock()
    controller.get_info.return_value = ready
    controller.is_newnym_available.return_value = newnym_available
    controller.get_newnym_wait.return_value = newnym_wait
    return controller


def settings(instances=2):
    pairs = tuple((10050 + n, 11050 + n) for n in range(1, instances + 1))
    return throwaway_settings(tor_instances=pairs)


class TorInstanceTest(unittest.IsolatedAsyncioTestCase):
    def test_connect_authenticates_on_loopback_control_port(self):
        controller = fake_controller()
        with mock.patch.object(tor_pool.Controller, "from_port", return_value=controller) as from_port:
            TorInstance(10051, 11051, "secret").connect()
        from_port.assert_called_once_with(address="127.0.0.1", port=11051)
        controller.authenticate.assert_called_once_with(password="secret")

    def test_is_ready_reads_circuit_established(self):
        instance = TorInstance(10051, 11051, "pw")
        instance.controller = fake_controller(ready="0")
        self.assertFalse(instance.is_ready())
        instance.controller.get_info.return_value = "1"
        self.assertTrue(instance.is_ready())
        instance.controller.get_info.assert_called_with("status/circuit-established", "0")

    def test_socks_url(self):
        self.assertEqual(TorInstance(10053, 11053, "pw").socks_url(), "socks5://127.0.0.1:10053")

    def test_success_rate_needs_ten_samples_and_rolls_over_fifty(self):
        instance = TorInstance(10051, 11051, "pw")
        for _ in range(9):
            instance.record(False)
        self.assertEqual(instance.success_rate(), 1.0)
        instance.record(False)
        self.assertEqual(instance.success_rate(), 0.0)
        for _ in range(50):
            instance.record(True)
        self.assertEqual(len(instance.outcomes), 50)
        self.assertEqual(instance.success_rate(), 1.0)

    async def test_rotate_signals_newnym(self):
        instance = TorInstance(10051, 11051, "pw")
        instance.controller = fake_controller()
        await instance.rotate()
        instance.controller.signal.assert_called_once_with(Signal.NEWNYM)
        self.assertIsNotNone(instance.last_rotation)

    async def test_rotate_waits_out_the_rate_limit(self):
        instance = TorInstance(10051, 11051, "pw")
        instance.controller = fake_controller(newnym_available=False, newnym_wait=7.5)
        with mock.patch.object(tor_pool.asyncio, "sleep", new=mock.AsyncMock()) as sleep:
            await instance.rotate()
        sleep.assert_awaited_once_with(7.5)
        instance.controller.signal.assert_called_once_with(Signal.NEWNYM)


class TorPoolTest(unittest.IsolatedAsyncioTestCase):
    async def test_start_drops_instances_that_never_get_a_circuit(self):
        pool = TorPool(settings(instances=3))
        controllers = [fake_controller("1"), fake_controller("0"), fake_controller("1")]
        with mock.patch.object(tor_pool.Controller, "from_port", side_effect=controllers), \
                mock.patch.object(tor_pool, "READY_TIMEOUT", 0.05), mock.patch.object(tor_pool, "READY_POLL", 0.01):
            with self.assertLogs("onioncollect.tor_pool", "WARNING") as logs:
                await pool.start()
        self.assertEqual([instance.socks_port for instance in pool.instances], [10051, 10053])
        controllers[1].close.assert_called_once()
        self.assertIn("10052", logs.output[0])

    async def test_start_waits_for_slow_instance(self):
        pool = TorPool(settings(instances=1))
        controller = fake_controller()
        controller.get_info.side_effect = ["0", "0", "1"]
        with mock.patch.object(tor_pool.Controller, "from_port", return_value=controller), \
                mock.patch.object(tor_pool, "READY_POLL", 0.01):
            await pool.start()
        self.assertEqual(len(pool.instances), 1)

    async def test_start_fails_when_nothing_is_ready(self):
        pool = TorPool(settings(instances=2))
        with mock.patch.object(tor_pool.Controller, "from_port", side_effect=lambda **_: fake_controller("0")), \
                mock.patch.object(tor_pool, "READY_TIMEOUT", 0.02), mock.patch.object(tor_pool, "READY_POLL", 0.01):
            with self.assertLogs("onioncollect.tor_pool", "WARNING"), self.assertRaises(RuntimeError):
                await pool.start()

    def test_assign_pins_workers_round_robin(self):
        pool = TorPool(settings(instances=3))
        ports = [pool.assign(worker).socks_port for worker in range(7)]
        self.assertEqual(ports, [10051, 10052, 10053, 10051, 10052, 10053, 10051])

    async def test_rotate_for_respects_cooldown(self):
        pool = TorPool(settings(instances=1))
        instance = pool.instances[0]
        instance.controller = fake_controller()
        await pool.rotate_for(instance)
        await pool.rotate_for(instance)
        self.assertEqual(instance.controller.signal.call_count, 1)
        instance.last_rotation -= tor_pool.ROTATE_COOLDOWN + 1
        await pool.rotate_for(instance)
        self.assertEqual(instance.controller.signal.call_count, 2)

    async def test_health_loop_rotates_only_unhealthy_instances(self):
        pool = TorPool(settings(instances=2))
        sick, healthy = pool.instances
        sick.controller, healthy.controller = fake_controller(), fake_controller()
        for _ in range(10):
            sick.record(False)
            healthy.record(True)
        with mock.patch.object(tor_pool, "HEALTH_INTERVAL", 0.01), self.assertLogs("onioncollect.tor_pool", "INFO"):
            task = asyncio.create_task(pool.health_loop())
            await asyncio.sleep(0.05)
            task.cancel()
        sick.controller.signal.assert_called_with(Signal.NEWNYM)
        healthy.controller.signal.assert_not_called()

    def test_stop_closes_every_controller(self):
        pool = TorPool(settings(instances=2))
        for instance in pool.instances:
            instance.controller = fake_controller()
        pool.stop()
        for instance in pool.instances:
            instance.controller.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
