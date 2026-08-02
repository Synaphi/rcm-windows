from __future__ import annotations

from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace
import traceback
import unittest

from rcm.core import RejectedError, UnavailableError
from rcm.ports import CredentialReference, CredentialTarget
from rcm.rdp import RdpLaunchReceipt, RdpRequest, RdpService
from rcm.adapters.windows import WindowsRdpLauncher
from rcm.runtime import (
    RuntimeCoordinator, RuntimeShutdownError, RuntimeState, RuntimeUnit,
)


_REFERENCE = CredentialReference(
    "credential://synthetic-store/worker_01"
)


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
        process_factory=lambda *_args, **_kwargs: SimpleNamespace(pid=41_001),
    )
    return RdpService(credentials=store, launcher=launcher), store


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
            process_factory=factory,
        )
        service = RdpService(credentials=store, launcher=launcher)
        request = RdpRequest(
            address="192.0.2.44",
            principal=r"SYNTHETIC\operator",
            port=3_390,
        )

        plan = service.plan(request)
        receipt = launcher.launch(plan)

        self.assertEqual("192.0.2.44:3390", plan.target)
        self.assertEqual("TERMSRV/192.0.2.44", plan.credential_target)
        self.assertEqual("rdp_192_0_2_44.rdp", plan.file_name)
        self.assertEqual(
            [
                "screen mode id:i:2",
                "use multimon:i:0",
                "desktopwidth:i:1280",
                "desktopheight:i:720",
                "session bpp:i:32",
                "full address:s:192.0.2.44:3390",
                "prompt for credentials:i:1",
                "authentication level:i:2",
                "enablecredsspsupport:i:1",
                r"username:s:SYNTHETIC\operator",
            ],
            plan.file_bytes.decode("utf-16").splitlines(),
        )
        self.assertEqual(
            [
                (
                    ("mstsc.exe", "rdp_192_0_2_44.rdp"),
                    {
                        "cwd": r"C:\Synthetic\Rdp",
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
        self.assertEqual("rdp_2001_db8__44.rdp", plan.file_name)

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

    def test_credential_failure_traceback_suppresses_private_cause(self) -> None:
        class ExplodingStore:
            def contains(self, _reference):
                raise RuntimeError("PRIVATE_CANARY_VALUE")

        launcher = WindowsRdpLauncher(
            filesystem=MemoryFilesystem(),
            directory=r"C:\Synthetic\Rdp",
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

    def test_cleanup_is_idempotent_and_refuses_fabricated_receipt_path(
        self,
    ) -> None:
        filesystem = MemoryFilesystem()
        filesystem.files[r"C:\Synthetic\unrelated.rdp"] = b"unrelated"
        launcher = WindowsRdpLauncher(
            filesystem=filesystem,
            directory=r"C:\Synthetic\Rdp",
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
