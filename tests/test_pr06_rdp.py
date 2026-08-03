from __future__ import annotations

from dataclasses import fields
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import traceback
import unittest

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
            self.assertEqual(9, filesystem.stat(str(artifact)).size)
            with self.assertRaises(ValueError):
                filesystem.write_bytes(
                    str(directory.parent / name),
                    b"outside",
                )
            filesystem.unlink(str(artifact))
            self.assertFalse(artifact.exists())

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
