from __future__ import annotations

from dataclasses import fields
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import traceback
import unittest
from unittest import mock

from rcm.core import CapabilityState, RejectedError, UnavailableError
from rcm.ports import CredentialReference, CredentialTarget
from rcm.rdp import RdpLaunchReceipt, RdpRequest, RdpService
from rcm.adapters.windows import LocalRdpFilesystem, WindowsRdpLauncher
from rcm.runtime import (
    RuntimeCoordinator, RuntimeShutdownError, RuntimeState, RuntimeUnit,
)


_REFERENCE = CredentialReference(
    "credential://synthetic-store/worker_01"
)
_MSTSC = r"C:\Synthetic\System32\mstsc.exe"
_TOKEN = "1" * 32


class SyntheticCredentialStore:
    def __init__(self, target: CredentialTarget | None) -> None:
        self.target = target
        self.events: list[tuple[str, CredentialReference]] = []

    def contains(self, reference: CredentialReference) -> bool:
        self.events.append(("contains", reference))
        return self.target is not None and self.target.reference == reference

    def resolve(self, reference: CredentialReference) -> CredentialTarget:
        self.events.append(("resolve", reference))
        if self.target is None:
            raise LookupError("synthetic missing credential reference")
        return self.target


class MemoryFilesystem:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.events: list[tuple[str, str]] = []

    def write_bytes(self, path: str, data: bytes) -> None:
        self.events.append(("write", path))
        self.files[path] = data

    def unlink(self, path: str, *, missing_ok: bool = False) -> None:
        self.events.append(("unlink", path))
        if path in self.files:
            del self.files[path]
        elif not missing_ok:
            raise FileNotFoundError(path)

    def recover_stale(self, path: str, *, missing_ok: bool = False) -> None:
        self.events.append(("recover_stale", path))
        self.unlink(path, missing_ok=missing_ok)

    def listdir(self, path: str) -> tuple[str, ...]:
        prefix = path.rstrip("\\") + "\\"
        return tuple(
            key[len(prefix):]
            for key in sorted(self.files)
            if key.startswith(prefix)
        )


def _service(
    *,
    target: str = "TERMSRV/192.0.2.44",
    principal: str = r"SYNTHETIC\operator",
) -> tuple[RdpService, SyntheticCredentialStore]:
    store = SyntheticCredentialStore(
        CredentialTarget(
            reference=_REFERENCE,
            target=target,
            principal=principal,
        )
    )
    launcher = WindowsRdpLauncher(
        filesystem=MemoryFilesystem(),
        directory=r"C:\Synthetic\Rdp",
        executable=_MSTSC,
        process_factory=lambda *_args, **_kwargs: SimpleNamespace(pid=41_001),
    )
    return RdpService(
        credentials=store,
        launcher=launcher,
        token_factory=lambda: _TOKEN,
    ), store


class RdpServiceTests(unittest.TestCase):
    def test_frozen_prompt_path_without_saved_credential_is_preserved(
        self,
    ) -> None:
        filesystem = MemoryFilesystem()
        launches: list[tuple[tuple[str, ...], dict[str, object]]] = []

        def factory(
            argv: tuple[str, ...],
            **kwargs: object,
        ) -> SimpleNamespace:
            launches.append((argv, kwargs))
            return SimpleNamespace(pid=41_001)

        store = SyntheticCredentialStore(
            None
        )
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=factory,
        )
        service = RdpService(
            credentials=store,
            launcher=launcher,
            token_factory=lambda: _TOKEN,
        )
        request = RdpRequest(
            address="192.0.2.44",
            principal=r"SYNTHETIC\operator",
            port=3_390,
        )

        plan = service.plan(request)
        receipt = launcher.launch(plan)

        self.assertEqual("192.0.2.44:3390", plan.target)
        self.assertEqual("TERMSRV/192.0.2.44", plan.credential_target)
        self.assertEqual(f"rcm_rdp_{_TOKEN}.rdp", plan.file_name)
        self.assertEqual(
            [
                "screen mode id:i:2",
                "use multimon:i:0",
                "keyboardhook:i:0",
                "desktopwidth:i:1280",
                "desktopheight:i:720",
                "session bpp:i:32",
                "full address:s:192.0.2.44:3390",
                "prompt for credentials:i:1",
                "authentication level:i:2",
                "enablecredsspsupport:i:1",
                "redirectclipboard:i:0",
                "drivestoredirect:s:",
                "devicestoredirect:s:",
                "usbdevicestoredirect:s:",
                "camerastoredirect:s:",
                "audiocapturemode:i:0",
                "redirectprinters:i:0",
                "redirectcomports:i:0",
                "redirectsmartcards:i:0",
                "redirectwebauthn:i:0",
                "redirectlocation:i:0",
                r"username:s:SYNTHETIC\operator",
            ],
            plan.file_bytes.decode("utf-16").splitlines(),
        )
        self.assertEqual(
            [
                (
                    (_MSTSC, rf"C:\Synthetic\Rdp\rcm_rdp_{_TOKEN}.rdp"),
                    {
                        "close_fds": True,
                    },
                )
            ],
            launches,
        )
        self.assertEqual(41_001, receipt.process_id)
        self.assertEqual(1, len(filesystem.files))

        service.cleanup(receipt)
        service.cleanup(receipt)

        self.assertEqual({}, filesystem.files)
        self.assertEqual([], store.events)

    def test_ipv6_endpoint_and_native_credential_target_are_distinct(
        self,
    ) -> None:
        service, _store = _service(
            target="TERMSRV/2001:db8::44",
        )

        plan = service.plan(
            RdpRequest(
                address="2001:0db8:0:0:0:0:0:44",
                principal=r"SYNTHETIC\operator",
                port=3_390,
                credential_reference=_REFERENCE,
            )
        )

        self.assertEqual("[2001:db8::44]:3390", plan.target)
        self.assertEqual("TERMSRV/2001:db8::44", plan.credential_target)
        self.assertEqual(f"rcm_rdp_{_TOKEN}.rdp", plan.file_name)
        self.assertIn(
            "prompt for credentials:i:0",
            plan.file_bytes.decode("utf-16").splitlines(),
        )

    def test_blank_principal_defers_identity_to_windows(self) -> None:
        service, _store = _service()

        plan = service.plan(RdpRequest("worker.example", ""))
        lines = plan.file_bytes.decode("utf-16").splitlines()

        self.assertNotIn("username:s:", lines)
        self.assertFalse(any(line.startswith("username:s:") for line in lines))
        self.assertIn("prompt for credentials:i:1", lines)

    def test_dns_address_is_canonical_and_accepts_configured_trailing_dot(self) -> None:
        request = RdpRequest("Worker.Example.", "")
        self.assertEqual("worker.example", request.address)
        self.assertEqual("worker.example:3389", request.target)

    def test_clipboard_is_explicit_opt_in_and_other_redirects_stay_off(self) -> None:
        service, _store = _service()

        plan = service.plan(RdpRequest(
            "worker.example",
            "SYNTHETIC_OPERATOR",
            redirect_clipboard=True,
        ))
        lines = plan.file_bytes.decode("utf-16").splitlines()

        self.assertIn("redirectclipboard:i:1", lines)
        self.assertIn("drivestoredirect:s:", lines)
        self.assertIn("devicestoredirect:s:", lines)
        self.assertIn("usbdevicestoredirect:s:", lines)
        self.assertIn("camerastoredirect:s:", lines)
        self.assertIn("audiocapturemode:i:0", lines)
        self.assertIn("redirectprinters:i:0", lines)
        self.assertIn("redirectsmartcards:i:0", lines)

    def test_every_launch_plan_has_a_collision_resistant_owned_name(self) -> None:
        tokens = iter(("1" * 32, "2" * 32, "3" * 32))
        store = SyntheticCredentialStore(None)
        launcher = WindowsRdpLauncher(
            filesystem=MemoryFilesystem(),
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(pid=41_006),
        )
        service = RdpService(
            credentials=store,
            launcher=launcher,
            token_factory=lambda: next(tokens),
        )

        names = {
            service.plan(RdpRequest("alpha-beta", "")).file_name,
            service.plan(RdpRequest("alpha.beta", "")).file_name,
            service.plan(RdpRequest("alpha-beta", "", 3_390)).file_name,
        }

        self.assertEqual(3, len(names))
        self.assertTrue(all(name.startswith("rcm_rdp_") for name in names))

    def test_principal_rejects_surrounding_whitespace(self) -> None:
        for principal in (" operator", "operator ", "\toperator"):
            with self.subTest(principal=principal):
                with self.assertRaises(ValueError):
                    RdpRequest("worker.example", principal)

    def test_reference_must_resolve_to_same_native_target(self) -> None:
        service, _store = _service(target="TERMSRV/192.0.2.99")

        with self.assertRaisesRegex(
            RejectedError,
            "binding does not match",
        ):
            service.plan(
                RdpRequest(
                    address="192.0.2.44",
                    principal=r"SYNTHETIC\operator",
                    credential_reference=_REFERENCE,
                )
            )

    def test_service_has_no_password_or_raw_credential_input(self) -> None:
        self.assertNotIn(
            "password",
            {field.name for field in fields(RdpRequest)},
        )
        unexpected = {"secret_material": object()}
        with self.assertRaises(TypeError):
            RdpRequest(  # type: ignore[call-arg]
                address="192.0.2.44",
                principal="SYNTHETIC_OPERATOR",
                credential_reference=_REFERENCE,
                **unexpected,
            )

    def test_failed_launch_removes_written_artifact(self) -> None:
        filesystem = MemoryFilesystem()

        def fail(*_args: object, **_kwargs: object) -> None:
            raise OSError("synthetic launch failure")

        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=fail,
        )
        service = RdpService(
            credentials=SyntheticCredentialStore(None),
            launcher=launcher,
        )

        with self.assertRaises(UnavailableError):
            service.launch(
                RdpRequest(
                    address="192.0.2.44",
                    principal="SYNTHETIC_OPERATOR",
                )
            )

        self.assertEqual({}, filesystem.files)

    def test_failed_launch_cleanup_failure_disables_and_tracks_artifact(
        self,
    ) -> None:
        class CleanupFailureFilesystem(MemoryFilesystem):
            fail_unlink = True

            def unlink(self, path: str, *, missing_ok: bool = False) -> None:
                if self.fail_unlink:
                    raise OSError("PRIVATE_CANARY_VALUE")
                super().unlink(path, missing_ok=missing_ok)

        filesystem = CleanupFailureFilesystem()

        def fail(*_args: object, **_kwargs: object) -> None:
            raise OSError("synthetic launch failure")

        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=fail,
        )
        service = RdpService(
            credentials=SyntheticCredentialStore(None),
            launcher=launcher,
        )

        with self.assertRaisesRegex(
            UnavailableError,
            "artifact could not be removed",
        ):
            service.launch(RdpRequest("worker.example", ""))
        self.assertEqual(1, len(filesystem.files))
        with self.assertRaisesRegex(
            UnavailableError,
            "directory is unavailable",
        ):
            service.launch(RdpRequest("other.example", ""))

        filesystem.fail_unlink = False
        service.cleanup_all()
        self.assertEqual({}, filesystem.files)
        self.assertTrue(launcher.join(0))

    def test_active_launch_token_collision_preserves_first_artifact(self) -> None:
        filesystem = MemoryFilesystem()
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(pid=41_008),
        )
        service = RdpService(
            credentials=SyntheticCredentialStore(None),
            launcher=launcher,
            token_factory=lambda: _TOKEN,
        )
        service.launch(RdpRequest("worker.example", ""))

        with self.assertRaisesRegex(UnavailableError, "already active"):
            service.launch(RdpRequest("other.example", ""))

        self.assertEqual(1, len(filesystem.files))

    def test_credential_failure_traceback_suppresses_private_cause(self) -> None:
        class ExplodingStore:
            def contains(self, _reference):
                raise RuntimeError("PRIVATE_CANARY_VALUE")

        launcher = WindowsRdpLauncher(
            filesystem=MemoryFilesystem(),
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(pid=41_004),
        )
        service = RdpService(credentials=ExplodingStore(), launcher=launcher)
        try:
            service.plan(RdpRequest(
                "192.0.2.44", "SYNTHETIC_OPERATOR",
                credential_reference=_REFERENCE,
            ))
        except UnavailableError as exc:
            rendered = "".join(traceback.format_exception(exc))
        else:
            self.fail("credential boundary did not fail closed")
        self.assertNotIn("PRIVATE_CANARY_VALUE", rendered)

    def test_launch_identity_failure_suppresses_private_cause(self) -> None:
        def fail_token() -> str:
            raise RuntimeError("PRIVATE_CANARY_VALUE")

        service = RdpService(
            credentials=SyntheticCredentialStore(None),
            launcher=WindowsRdpLauncher(
                filesystem=MemoryFilesystem(),
                directory=r"C:\Synthetic\Rdp",
                executable=_MSTSC,
                process_factory=lambda *_args, **_kwargs: SimpleNamespace(
                    pid=41_009
                ),
            ),
            token_factory=fail_token,
        )
        try:
            service.plan(RdpRequest("worker.example", ""))
        except UnavailableError as exc:
            rendered = "".join(traceback.format_exception(exc))
        else:
            self.fail("launch identity failure did not fail closed")
        self.assertNotIn("PRIVATE_CANARY_VALUE", rendered)

    def test_cleanup_is_idempotent_and_refuses_fabricated_receipt_path(
        self,
    ) -> None:
        filesystem = MemoryFilesystem()
        filesystem.files[r"C:\Synthetic\unrelated.rdp"] = b"unrelated"
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(pid=41_002),
        )
        forged = RdpLaunchReceipt(
            process_id=41_002,
            artifact_path=r"C:\Synthetic\unrelated.rdp",
        )

        launcher.cleanup(forged)
        launcher.cleanup(forged)

        self.assertEqual(
            b"unrelated",
            filesystem.files[r"C:\Synthetic\unrelated.rdp"],
        )

    def test_launch_collision_never_deletes_a_preexisting_owned_name(
        self,
    ) -> None:
        class ExclusiveMemoryFilesystem(MemoryFilesystem):
            def write_bytes(self, path: str, data: bytes) -> None:
                if path in self.files:
                    raise FileExistsError(path)
                super().write_bytes(path, data)

        filesystem = ExclusiveMemoryFilesystem()
        artifact = rf"C:\Synthetic\Rdp\rcm_rdp_{_TOKEN}.rdp"
        filesystem.files[artifact] = b"preexisting"
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(
                pid=41_012
            ),
        )
        service = RdpService(
            credentials=SyntheticCredentialStore(None),
            launcher=launcher,
            token_factory=lambda: _TOKEN,
        )

        with self.assertRaisesRegex(
            UnavailableError,
            "native RDP client could not be launched",
        ):
            service.launch(RdpRequest("worker.example", ""))

        self.assertEqual(b"preexisting", filesystem.files[artifact])
        self.assertNotIn(("unlink", artifact), filesystem.events)
        self.assertTrue(launcher.join(0))

    def test_mstsc_resolution_failure_never_touches_the_planned_path(
        self,
    ) -> None:
        class MissingClientLauncher(WindowsRdpLauncher):
            def _mstsc_path(self) -> str:
                raise OSError("synthetic native client failure")

        filesystem = MemoryFilesystem()
        artifact = rf"C:\Synthetic\Rdp\rcm_rdp_{_TOKEN}.rdp"
        filesystem.files[artifact] = b"preexisting"
        launcher = MissingClientLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(
                pid=41_013
            ),
        )
        service = RdpService(
            credentials=SyntheticCredentialStore(None),
            launcher=launcher,
            token_factory=lambda: _TOKEN,
        )

        with self.assertRaisesRegex(
            UnavailableError,
            "native RDP client could not be launched",
        ):
            service.launch(RdpRequest("worker.example", ""))

        self.assertEqual(b"preexisting", filesystem.files[artifact])
        self.assertEqual([], filesystem.events)

    def test_process_factory_file_exists_error_removes_new_artifact(self) -> None:
        filesystem = MemoryFilesystem()
        artifact = rf"C:\Synthetic\Rdp\rcm_rdp_{_TOKEN}.rdp"
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=mock.Mock(side_effect=FileExistsError("synthetic")),
        )
        service = RdpService(
            credentials=SyntheticCredentialStore(None),
            launcher=launcher,
            token_factory=lambda: _TOKEN,
        )

        with self.assertRaises(UnavailableError):
            service.launch(RdpRequest("worker.example", ""))

        self.assertNotIn(artifact, filesystem.files)
        self.assertIn(("unlink", artifact), filesystem.events)
        self.assertTrue(launcher.join(0))

    def test_partial_write_failure_removes_only_the_new_artifact(self) -> None:
        class PartialFailureFilesystem(MemoryFilesystem):
            def write_bytes(self, path: str, data: bytes) -> None:
                super().write_bytes(path, data)
                super().unlink(path, missing_ok=False)
                raise OSError("synthetic partial write")

        filesystem = PartialFailureFilesystem()
        artifact = rf"C:\Synthetic\Rdp\rcm_rdp_{_TOKEN}.rdp"
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(
                pid=41_014
            ),
        )
        service = RdpService(
            credentials=SyntheticCredentialStore(None),
            launcher=launcher,
            token_factory=lambda: _TOKEN,
        )

        with self.assertRaises(UnavailableError):
            service.launch(RdpRequest("worker.example", ""))

        self.assertNotIn(artifact, filesystem.files)
        self.assertEqual(
            [("write", artifact), ("unlink", artifact)],
            filesystem.events,
        )
        self.assertTrue(launcher.join(0))

    def test_generic_precreate_failure_never_deletes_an_existing_path(
        self,
    ) -> None:
        class PrecreateFailureFilesystem(MemoryFilesystem):
            def write_bytes(self, path: str, data: bytes) -> None:
                del path, data
                raise PermissionError("synthetic pre-create failure")

        filesystem = PrecreateFailureFilesystem()
        artifact = rf"C:\Synthetic\Rdp\rcm_rdp_{_TOKEN}.rdp"
        filesystem.files[artifact] = b"preexisting"
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(pid=1),
        )
        service = RdpService(
            credentials=SyntheticCredentialStore(None),
            launcher=launcher,
            token_factory=lambda: _TOKEN,
        )

        with self.assertRaises(UnavailableError):
            service.launch(RdpRequest("worker.example", ""))

        self.assertEqual(b"preexisting", filesystem.files[artifact])
        self.assertNotIn(("unlink", artifact), filesystem.events)

    def test_local_filesystem_removes_a_created_partial_write(self) -> None:
        if os.name != "nt":
            self.skipTest("requires the Windows handle-backed write path")
        from rcm.adapters import windows as windows_adapter

        artifact = rf"C:\Synthetic\Rdp\rcm_rdp_{_TOKEN}.rdp"
        directory_lease = mock.Mock()
        details = windows_adapter._WindowsLocalFileDetails(
            windows_adapter._OWNED_RDP_FILE_ATTRIBUTES,
            0,
            0,
            7,
            1,
            8,
        )

        with (
            mock.patch("rcm.setup._assert_local_metadata_root"),
            mock.patch.object(
                LocalRdpFilesystem,
                "_acquire_directory",
                return_value=directory_lease,
            ),
            mock.patch(
                "rcm.adapters.windows._open_windows_local_file",
                return_value=41_016,
            ),
            mock.patch(
                "rcm.adapters.windows._windows_local_file_details",
                return_value=details,
            ),
            mock.patch(
                "rcm.adapters.windows._write_windows_local_file",
                side_effect=OSError("synthetic partial write"),
            ) as write_file,
            mock.patch(
                "rcm.adapters.windows._mark_windows_local_file_for_delete"
            ) as mark_delete,
            mock.patch(
                "rcm.adapters.windows._close_windows_local_file"
            ) as close,
        ):
            filesystem = LocalRdpFilesystem(r"C:\Synthetic\Rdp")
            with self.assertRaises(OSError):
                filesystem.write_bytes(artifact, b"synthetic")

        write_file.assert_called_once_with(41_016, b"synthetic")
        mark_delete.assert_called_once_with(41_016)
        close.assert_called_once_with(41_016)
        directory_lease.close.assert_called_once_with()

    def test_runtime_cleanup_never_terminates_the_native_client(self) -> None:
        filesystem = MemoryFilesystem()
        process = SimpleNamespace(
            pid=41_015,
            terminate=mock.Mock(side_effect=AssertionError("must not terminate")),
            kill=mock.Mock(side_effect=AssertionError("must not kill")),
            wait=mock.Mock(side_effect=AssertionError("must not wait")),
        )
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: process,
        )
        service = RdpService(
            credentials=SyntheticCredentialStore(None),
            launcher=launcher,
            token_factory=lambda: _TOKEN,
        )
        runtime = RuntimeCoordinator((RuntimeUnit("rdp-artifacts", launcher),))
        runtime.start()

        receipt = service.launch(RdpRequest("worker.example", ""))
        stopped = runtime.stop()

        self.assertEqual(41_015, receipt.process_id)
        self.assertIs(RuntimeState.STOPPED, stopped.state)
        self.assertEqual({}, filesystem.files)
        self.assertTrue(launcher.join(0))
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        process.wait.assert_not_called()

    def test_cleanup_all_removes_every_launcher_owned_artifact(self) -> None:
        filesystem = MemoryFilesystem()
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(pid=41_003),
        )
        service = RdpService(
            credentials=SyntheticCredentialStore(None), launcher=launcher,
        )
        service.launch(RdpRequest("192.0.2.44", "SYNTHETIC_OPERATOR"))
        service.launch(RdpRequest("192.0.2.45", "SYNTHETIC_OPERATOR"))
        self.assertEqual(2, len(filesystem.files))
        service.cleanup_all()
        self.assertEqual({}, filesystem.files)

    def test_startup_cleanup_removes_only_owned_artifacts(self) -> None:
        filesystem = MemoryFilesystem()
        owned = rf"C:\Synthetic\Rdp\rcm_rdp_{'a' * 32}.rdp"
        foreign = r"C:\Synthetic\Rdp\personal.rdp"
        filesystem.files.update({owned: b"stale", foreign: b"keep"})
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(pid=41_007),
        )
        cancellation = SimpleNamespace(raise_if_cancelled=lambda: None)

        launcher.start(cancellation)

        self.assertNotIn(owned, filesystem.files)
        self.assertEqual(b"keep", filesystem.files[foreign])
        self.assertIn(("recover_stale", owned), filesystem.events)

    def test_stale_recovery_retry_uses_the_prior_process_boundary(self) -> None:
        class HeldReaderFilesystem(MemoryFilesystem):
            sharing_failure = True

            def recover_stale(
                self,
                path: str,
                *,
                missing_ok: bool = False,
            ) -> None:
                self.events.append(("recover_attempt", path))
                if self.sharing_failure:
                    raise PermissionError("synthetic sharing violation")
                super().recover_stale(path, missing_ok=missing_ok)

        filesystem = HeldReaderFilesystem()
        owned = rf"C:\Synthetic\Rdp\rcm_rdp_{'b' * 32}.rdp"
        filesystem.files[owned] = b"stale"
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=mock.Mock(
                side_effect=AssertionError("must not start a process")
            ),
        )

        launcher.start(SimpleNamespace(raise_if_cancelled=lambda: None))

        self.assertFalse(launcher.join(0))
        self.assertEqual(b"stale", filesystem.files[owned])
        filesystem.sharing_failure = False
        launcher.cleanup_all()

        self.assertNotIn(owned, filesystem.files)
        self.assertTrue(launcher.join(0))
        self.assertEqual(
            [("recover_attempt", owned), ("recover_attempt", owned)],
            [event for event in filesystem.events if event[0] == "recover_attempt"],
        )

    def test_startup_unlink_failure_is_tracked_for_shutdown_retry(self) -> None:
        class CleanupFailureFilesystem(MemoryFilesystem):
            fail_unlink = True

            def unlink(self, path: str, *, missing_ok: bool = False) -> None:
                if self.fail_unlink:
                    raise OSError("PRIVATE_CANARY_VALUE")
                super().unlink(path, missing_ok=missing_ok)

        filesystem = CleanupFailureFilesystem()
        owned = rf"C:\Synthetic\Rdp\rcm_rdp_{'a' * 32}.rdp"
        filesystem.files[owned] = b"stale"
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(
                pid=41_011
            ),
        )

        launcher.start(SimpleNamespace(raise_if_cancelled=lambda: None))

        self.assertFalse(launcher.join(0))
        with self.assertRaisesRegex(
            UnavailableError,
            "directory is unavailable",
        ):
            RdpService(
                credentials=SyntheticCredentialStore(None),
                launcher=launcher,
            ).launch(RdpRequest("worker.example", ""))
        filesystem.fail_unlink = False
        launcher.cleanup_all()
        self.assertEqual({}, filesystem.files)
        self.assertTrue(launcher.join(0))

    def test_startup_cleanup_failure_disables_rdp_without_failing_runtime(self) -> None:
        class CleanupFailureFilesystem(MemoryFilesystem):
            fail_listdir = True

            def listdir(self, _path: str) -> tuple[str, ...]:
                if self.fail_listdir:
                    raise OSError("PRIVATE_CANARY_VALUE")
                return super().listdir(_path)

        filesystem = CleanupFailureFilesystem()
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(pid=41_010),
        )
        runtime = RuntimeCoordinator((RuntimeUnit("rdp-artifacts", launcher),))

        self.assertEqual(RuntimeState.RUNNING, runtime.start().state)
        with self.assertRaisesRegex(UnavailableError, "directory is unavailable"):
            RdpService(
                credentials=SyntheticCredentialStore(None),
                launcher=launcher,
                token_factory=lambda: _TOKEN,
            ).launch(RdpRequest("worker.example", ""))
        self.assertEqual({}, filesystem.files)
        with self.assertRaises(RuntimeShutdownError):
            runtime.stop()
        self.assertEqual(RuntimeState.FAILED, runtime.snapshot().state)
        filesystem.fail_listdir = False
        self.assertEqual(RuntimeState.STOPPED, runtime.stop().state)

    def test_launcher_rejects_relative_remote_and_wrong_executable_paths(self) -> None:
        for directory in (
            "relative",
            "\\" * 2 + r"server\share\rdp",
            r"C:\Synthetic\..\Rdp",
            r"C:\Synthetic\Rdp:stream",
        ):
            with self.subTest(directory=directory):
                with self.assertRaises(ValueError):
                    WindowsRdpLauncher(
                        filesystem=MemoryFilesystem(),
                        directory=directory,
                        executable=_MSTSC,
                    )
        with self.assertRaises(ValueError):
            WindowsRdpLauncher(
                filesystem=MemoryFilesystem(),
                directory=r"C:\Synthetic\Rdp",
                executable=r"C:\Synthetic\System32\cmd.exe",
            )

    def test_local_rdp_filesystem_is_confined_to_owned_directory(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows artifact filesystem contract")
        with tempfile.TemporaryDirectory(prefix="rcm-rdp-files-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            filesystem = LocalRdpFilesystem(str(directory))
            name = f"rcm_rdp_{'a' * 32}.rdp"
            artifact = directory / name

            filesystem.write_bytes(str(artifact), b"synthetic")
            observed = filesystem.read_bytes(str(artifact), limit=32)

            self.assertEqual(b"synthetic", observed)
            self.assertEqual((name,), filesystem.listdir(str(directory)))
            file_stat = filesystem.stat(str(artifact))
            self.assertEqual(9, file_stat.size)
            self.assertEqual(artifact.stat().st_mtime_ns, file_stat.modified_ns)
            with self.assertRaises(ValueError):
                filesystem.write_bytes(
                    str(directory.parent / name),
                    b"outside",
                )
            filesystem.unlink(str(artifact))
            self.assertFalse(artifact.exists())

    def test_local_rdp_stale_recovery_accepts_partial_and_full_marked_files(
        self,
    ) -> None:
        if os.name != "nt":
            self.skipTest("Windows marked RDP recovery contract")
        from rcm.adapters import windows as windows_adapter

        with tempfile.TemporaryDirectory(prefix="rcm-rdp-stale-marked-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            filesystem = LocalRdpFilesystem(str(directory))
            payloads = (b"\xff", b"\xff\xfe" + b"synthetic-rdp" * 32)

            for index, payload in enumerate(payloads):
                with self.subTest(index=index):
                    artifact = directory / (
                        f"rcm_rdp_{index:032x}.rdp"
                    )
                    windows_adapter._write_exclusive_local_file(
                        str(artifact), payload
                    )
                    attributes = os.stat(artifact).st_file_attributes
                    self.assertEqual(
                        windows_adapter._OWNED_RDP_FILE_ATTRIBUTES,
                        attributes
                        & windows_adapter._OWNED_RDP_FILE_ATTRIBUTES,
                    )

                    filesystem.recover_stale(str(artifact))

                    self.assertFalse(artifact.exists())

    def test_owned_rdp_marker_allows_inherited_local_storage_attributes(
        self,
    ) -> None:
        from rcm.adapters import windows as windows_adapter

        def details(attributes: int) -> object:
            return windows_adapter._WindowsLocalFileDetails(
                attributes,
                128,
                0,
                1,
                1,
                1,
            )

        marker = windows_adapter._OWNED_RDP_FILE_ATTRIBUTES
        for inherited in (0x200, 0x800, 0x2000, 0x4000, 0x8000, 0x20000):
            with self.subTest(inherited=inherited):
                self.assertTrue(
                    windows_adapter._owned_rdp_file_details_are_valid(
                        details(marker | inherited)
                    )
                )
        for forbidden in (0x10, 0x40, 0x400):
            with self.subTest(forbidden=forbidden):
                self.assertFalse(
                    windows_adapter._owned_rdp_file_details_are_valid(
                        details(marker | forbidden)
                    )
                )

    def test_local_rdp_stale_recovery_preserves_ambiguous_files(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows marked RDP recovery contract")
        from rcm.adapters import windows as windows_adapter

        with tempfile.TemporaryDirectory(prefix="rcm-rdp-stale-ambiguous-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            filesystem = LocalRdpFilesystem(str(directory))
            unmarked = directory / f"rcm_rdp_{'3' * 32}.rdp"
            partial_marker = directory / f"rcm_rdp_{'4' * 32}.rdp"
            oversized = directory / f"rcm_rdp_{'5' * 32}.rdp"
            rejected = directory / f"rcm_rdp_{'9' * 32}.rdp"
            unmarked.write_bytes(b"foreign")
            handle = windows_adapter._open_windows_local_file(
                str(partial_marker),
                access=0x40000000 | 0x00010000,
                creation=1,
                file_attributes=0x00000002 | 0x00000100,
            )
            windows_adapter._close_windows_local_file(handle)
            oversized_handle = windows_adapter._open_windows_local_file(
                str(oversized),
                access=0x40000000 | 0x00010000,
                creation=1,
                file_attributes=(
                    windows_adapter._OWNED_RDP_FILE_ATTRIBUTES
                ),
            )
            try:
                windows_adapter._write_windows_local_file(
                    oversized_handle, b"x" * 65_537
                )
            finally:
                windows_adapter._close_windows_local_file(oversized_handle)
            with self.assertRaisesRegex(ValueError, "owned-file limit"):
                windows_adapter._write_exclusive_local_file(
                    str(rejected), b"x" * 65_537
                )
            self.assertFalse(rejected.exists())

            for artifact in (unmarked, partial_marker, oversized):
                with self.subTest(artifact=artifact.name):
                    with self.assertRaisesRegex(
                        OSError,
                        "ownership marker is unavailable",
                    ):
                        filesystem.recover_stale(str(artifact))
                    self.assertTrue(artifact.exists())

    def test_local_rdp_stale_recovery_preserves_multilink(
        self,
    ) -> None:
        if os.name != "nt":
            self.skipTest("Windows marked RDP recovery contract")
        from rcm.adapters import windows as windows_adapter

        with tempfile.TemporaryDirectory(prefix="rcm-rdp-stale-alias-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            filesystem = LocalRdpFilesystem(str(directory))
            multilink = directory / f"rcm_rdp_{'6' * 32}.rdp"
            alias = directory / "foreign-hard-link.rdp"
            windows_adapter._write_exclusive_local_file(
                str(multilink), b"synthetic"
            )
            try:
                os.link(multilink, alias)
            except OSError as error:
                multilink.unlink(missing_ok=True)
                self.skipTest(f"Windows hard links unavailable: {error}")

            with self.assertRaisesRegex(OSError, "ownership marker"):
                filesystem.recover_stale(str(multilink))
            self.assertTrue(multilink.exists())
            self.assertTrue(alias.exists())

    def test_local_rdp_stale_recovery_preserves_reparse(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows reparse recovery contract")

        with tempfile.TemporaryDirectory(prefix="rcm-rdp-stale-reparse-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            filesystem = LocalRdpFilesystem(str(directory))

            target = directory / "foreign-target.rdp"
            reparse = directory / f"rcm_rdp_{'7' * 32}.rdp"
            target.write_bytes(b"foreign")
            try:
                os.symlink(target, reparse)
            except OSError as error:
                self.skipTest(f"Windows symlinks unavailable: {error}")

            with self.assertRaisesRegex(OSError, "ownership marker"):
                filesystem.recover_stale(str(reparse))
            self.assertTrue(reparse.is_symlink())
            self.assertEqual(b"foreign", target.read_bytes())

    def test_local_rdp_active_cleanup_preserves_multilink(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows active-link ownership contract")
        from rcm.adapters import windows as windows_adapter

        with tempfile.TemporaryDirectory(prefix="rcm-rdp-active-link-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            artifact = directory / f"rcm_rdp_{'a' * 32}.rdp"
            alias = directory / "foreign-active-link.rdp"
            filesystem = LocalRdpFilesystem(str(directory))
            filesystem.write_bytes(str(artifact), b"synthetic-rdp")
            os.link(artifact, alias)

            with self.assertRaisesRegex(OSError, "ownership changed"):
                filesystem.unlink(str(artifact))
            self.assertTrue(artifact.exists())
            self.assertTrue(alias.exists())
            self.assertEqual(b"synthetic-rdp", alias.read_bytes())
            state = filesystem._owned_artifacts[str(artifact).casefold()]
            windows_adapter._close_windows_local_file(state.handle)
            state.handle = None
            alias.unlink()
            filesystem.unlink(str(artifact))

    def test_local_rdp_guard_rejects_multilink_handoff(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows handoff-link ownership contract")
        from rcm.adapters import windows as windows_adapter

        with tempfile.TemporaryDirectory(prefix="rcm-rdp-handoff-link-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            artifact = directory / f"rcm_rdp_{'d' * 32}.rdp"
            alias = directory / "foreign-handoff-link.rdp"
            filesystem = LocalRdpFilesystem(str(directory))
            original_write = windows_adapter._write_exclusive_local_file

            def link_after_writer_close(path: str, data: bytes) -> str:
                identity = original_write(path, data)
                os.link(path, alias)
                return identity

            with (
                mock.patch(
                    "rcm.adapters.windows._write_exclusive_local_file",
                    side_effect=link_after_writer_close,
                ),
                self.assertRaisesRegex(
                    OSError,
                    "guard could not be established",
                ),
            ):
                filesystem.write_bytes(str(artifact), b"synthetic-rdp")

            self.assertTrue(artifact.exists())
            self.assertTrue(alias.exists())
            self.assertEqual(b"synthetic-rdp", alias.read_bytes())
            alias.unlink()
            artifact.unlink()

    def test_local_rdp_held_reader_is_recovered_at_shutdown(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows handle-sharing recovery contract")
        from rcm.adapters import windows as windows_adapter

        with tempfile.TemporaryDirectory(prefix="rcm-rdp-stale-held-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            artifact = directory / f"rcm_rdp_{'8' * 32}.rdp"
            windows_adapter._write_exclusive_local_file(
                str(artifact), b"synthetic"
            )
            reader = windows_adapter._open_windows_local_file(
                str(artifact),
                access=0x80000000,
                creation=3,
            )
            process_factory = mock.Mock(
                side_effect=AssertionError("must not start a process")
            )
            launcher = WindowsRdpLauncher(
                filesystem=LocalRdpFilesystem(str(directory)),
                directory=str(directory),
                executable=_MSTSC,
                process_factory=process_factory,
            )
            try:
                launcher.start(
                    SimpleNamespace(raise_if_cancelled=lambda: None)
                )
                self.assertFalse(launcher.join(0))
                self.assertTrue(artifact.exists())
            finally:
                windows_adapter._close_windows_local_file(reader)

            launcher.cleanup_all()

            self.assertFalse(artifact.exists())
            self.assertTrue(launcher.join(0))
            process_factory.assert_not_called()

    def test_local_rdp_guard_preserves_launch_bytes_until_cleanup(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows handle identity contract")
        with tempfile.TemporaryDirectory(prefix="rcm-rdp-identity-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            filesystem = LocalRdpFilesystem(str(directory))
            consumed: list[bytes] = []

            def consume_while_attacked(
                argv: tuple[str, ...],
                **_kwargs: object,
            ) -> SimpleNamespace:
                artifact = Path(argv[1])
                with self.assertRaises(OSError):
                    artifact.unlink()
                with self.assertRaises(OSError):
                    artifact.write_bytes(b"replacement")
                consumed.append(artifact.read_bytes())
                return SimpleNamespace(pid=41_017)

            launcher = WindowsRdpLauncher(
                filesystem=filesystem,
                directory=str(directory),
                executable=_MSTSC,
                process_factory=consume_while_attacked,
            )
            service = RdpService(
                credentials=SyntheticCredentialStore(None),
                launcher=launcher,
                token_factory=lambda: _TOKEN,
            )
            receipt = service.launch(RdpRequest("worker.example", ""))
            artifact = Path(receipt.artifact_path)

            self.assertEqual(1, len(consumed))
            self.assertIn(
                "full address:s:worker.example:3389",
                consumed[0].decode("utf-16").splitlines(),
            )
            with self.assertRaises(OSError):
                artifact.unlink()
            service.cleanup(receipt)
            self.assertTrue(launcher.join(0))
            self.assertFalse(artifact.exists())

    def test_local_rdp_guard_cleans_up_after_process_launch_failure(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows handle identity contract")
        with tempfile.TemporaryDirectory(prefix="rcm-rdp-guard-fail-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            filesystem = LocalRdpFilesystem(str(directory))
            launcher = WindowsRdpLauncher(
                filesystem=filesystem,
                directory=str(directory),
                executable=_MSTSC,
                process_factory=mock.Mock(
                    side_effect=OSError("synthetic launch failure")
                ),
            )
            service = RdpService(
                credentials=SyntheticCredentialStore(None),
                launcher=launcher,
                token_factory=lambda: _TOKEN,
            )

            with self.assertRaises(UnavailableError):
                service.launch(RdpRequest("worker.example", ""))

            self.assertEqual((), filesystem.listdir(str(directory)))
            self.assertTrue(launcher.join(0))

    def test_local_rdp_guard_rejects_same_identity_content_race(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows handle identity contract")
        from rcm.adapters import windows as windows_adapter

        with tempfile.TemporaryDirectory(prefix="rcm-rdp-content-race-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            filesystem = LocalRdpFilesystem(str(directory))
            artifact = directory / f"rcm_rdp_{'c' * 32}.rdp"
            original_write = windows_adapter._write_exclusive_local_file

            def mutate_after_writer_close(path: str, data: bytes) -> str:
                identity = original_write(path, data)
                mutation_handle = windows_adapter._open_windows_local_file(
                    path,
                    access=0x40000000,
                    creation=3,
                )
                try:
                    windows_adapter._write_windows_local_file(
                        mutation_handle, b"replacement-rdp-bytes"
                    )
                finally:
                    windows_adapter._close_windows_local_file(mutation_handle)
                return identity

            with (
                mock.patch(
                    "rcm.adapters.windows._write_exclusive_local_file",
                    side_effect=mutate_after_writer_close,
                ),
                self.assertRaisesRegex(OSError, "contents changed"),
            ):
                filesystem.write_bytes(str(artifact), b"original-rdp-bytes")

            self.assertFalse(artifact.exists())
            self.assertEqual((), filesystem.listdir(str(directory)))

    def test_local_rdp_write_locks_directory_and_file_against_rename(
        self,
    ) -> None:
        if os.name != "nt":
            self.skipTest("Windows handle-sharing contract")
        from rcm.adapters import windows as windows_adapter

        with tempfile.TemporaryDirectory(prefix="rcm-rdp-locks-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            artifact = directory / f"rcm_rdp_{'b' * 32}.rdp"
            renamed_directory = directory.with_name("redirected")
            renamed_artifact = artifact.with_name("redirected.rdp")
            original_write = windows_adapter._write_windows_local_file
            observations: list[str] = []

            def write_while_attacked(handle: int, data: bytes) -> None:
                with self.assertRaises(OSError):
                    directory.rename(renamed_directory)
                observations.append("directory-locked")
                with self.assertRaises(OSError):
                    artifact.rename(renamed_artifact)
                observations.append("file-locked")
                original_write(handle, data)

            filesystem = LocalRdpFilesystem(str(directory))
            with mock.patch(
                "rcm.adapters.windows._write_windows_local_file",
                side_effect=write_while_attacked,
            ):
                filesystem.write_bytes(str(artifact), b"synthetic")

            self.assertEqual(
                ["directory-locked", "file-locked"],
                observations,
            )
            self.assertEqual(b"synthetic", artifact.read_bytes())
            filesystem.unlink(str(artifact))

    def test_windows_capability_resolves_existing_system_mstsc(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows native RDP capability")
        with tempfile.TemporaryDirectory(prefix="rcm-rdp-capability-") as temporary:
            directory = Path(temporary, "rdp")
            directory.mkdir()
            launcher = WindowsRdpLauncher(
                filesystem=LocalRdpFilesystem(str(directory)),
                directory=str(directory),
            )

            capability = launcher.capability()
            executable = Path(launcher._mstsc_path())

        self.assertIs(CapabilityState.AVAILABLE, capability.state)
        self.assertEqual("mstsc.exe", executable.name.casefold())
        self.assertTrue(executable.is_file())

    def test_runtime_cleanup_continues_after_one_artifact_failure(self) -> None:
        class SelectiveFailureFilesystem(MemoryFilesystem):
            failed_path: str | None = None

            def unlink(self, path: str, *, missing_ok: bool = False) -> None:
                if path == self.failed_path:
                    raise OSError("PRIVATE_CANARY_VALUE")
                super().unlink(path, missing_ok=missing_ok)

        filesystem = SelectiveFailureFilesystem()
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
            executable=_MSTSC,
            process_factory=lambda *_args, **_kwargs: SimpleNamespace(pid=41_005),
        )
        service = RdpService(
            credentials=SyntheticCredentialStore(None), launcher=launcher,
        )
        runtime = RuntimeCoordinator((RuntimeUnit("rdp-artifacts", launcher),))
        runtime.start()
        service.launch(RdpRequest("192.0.2.44", "SYNTHETIC_OPERATOR"))
        service.launch(RdpRequest("192.0.2.45", "SYNTHETIC_OPERATOR"))
        filesystem.failed_path = next(iter(filesystem.files))

        with self.assertRaises(RuntimeShutdownError):
            runtime.stop()
        self.assertEqual(1, len(filesystem.files))
        self.assertEqual(RuntimeState.FAILED, runtime.snapshot().state)
        with self.assertRaisesRegex(
            UnavailableError,
            "directory is unavailable",
        ):
            service.launch(RdpRequest("192.0.2.46", ""))
        filesystem.failed_path = None
        self.assertEqual(RuntimeState.STOPPED, runtime.stop().state)
        self.assertEqual({}, filesystem.files)

    def test_effectful_windows_imports_are_method_local(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src"
            / "rcm"
            / "adapters"
            / "windows.py"
        ).read_text(encoding="utf-8")
        prefix = source.split("class WindowsRdpLauncher:", maxsplit=1)[0]
        self.assertNotIn("import subprocess", prefix)
        self.assertNotIn("import shutil", prefix)


if __name__ == "__main__":
    unittest.main()
