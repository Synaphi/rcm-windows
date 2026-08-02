"""Lazy Windows host adapters."""

from __future__ import annotations

import ntpath
from typing import Any, Callable

from ..core import (
    Capability,
    CapabilityState,
    UnavailableError,
    UnsupportedError,
)
from ..rdp import RdpLaunchPlan, RdpLaunchReceipt
from ..ports import Filesystem


class WindowsRdpLauncher:
    """Launch ``mstsc.exe`` with an argv tuple and no credential material."""

    def __init__(
        self,
        *,
        filesystem: Filesystem,
        directory: str,
        process_factory: Callable[..., Any] | None = None,
    ) -> None:
        if (
            type(directory) is not str
            or not directory
            or any(ord(character) < 32 for character in directory)
        ):
            raise ValueError("RDP directory must be a safe non-empty path")
        self._filesystem = filesystem
        self._directory = directory
        self._process_factory = process_factory
        self._issued: dict[int, RdpLaunchReceipt] = {}

    def capability(self) -> Capability:
        import sys

        if sys.platform != "win32":
            return Capability(
                "rdp",
                CapabilityState.UNSUPPORTED,
                "windows_only",
            )
        import shutil

        if shutil.which("mstsc.exe") is None:
            return Capability(
                "rdp",
                CapabilityState.UNAVAILABLE,
                "native_client_missing",
            )
        return Capability("rdp", CapabilityState.AVAILABLE)

    def launch(self, plan: RdpLaunchPlan) -> RdpLaunchReceipt:
        if not isinstance(plan, RdpLaunchPlan):
            raise TypeError("plan must be an RdpLaunchPlan")
        factory = self._process_factory
        if factory is None:
            import sys

            if sys.platform != "win32":
                raise UnsupportedError(
                    "the native RDP launcher is available only on Windows"
                )
            import subprocess

            factory = subprocess.Popen
        artifact_path = ntpath.join(self._directory, plan.file_name)
        try:
            self._filesystem.write_bytes(artifact_path, plan.file_bytes)
            process = factory(
                ("mstsc.exe", plan.file_name),
                cwd=self._directory,
                close_fds=True,
            )
            receipt = RdpLaunchReceipt(
                process_id=getattr(process, "pid", None),
                artifact_path=artifact_path,
            )
        except Exception:
            try:
                self._filesystem.unlink(artifact_path, missing_ok=True)
            except Exception:
                raise UnavailableError(
                    "the RDP launch failed and its artifact could not be removed"
                ) from None
            raise UnavailableError(
                "the native RDP client could not be launched"
            ) from None
        self._issued[id(receipt)] = receipt
        return receipt

    def cleanup(self, receipt: RdpLaunchReceipt) -> None:
        if not isinstance(receipt, RdpLaunchReceipt):
            raise TypeError("receipt must be an RdpLaunchReceipt")
        if self._issued.get(id(receipt)) is not receipt:
            return
        try:
            self._filesystem.unlink(
                receipt.artifact_path,
                missing_ok=True,
            )
        except Exception:
            raise UnavailableError(
                "the RDP launch artifact could not be removed"
            ) from None
        self._issued.pop(id(receipt), None)

    def cleanup_all(self) -> None:
        failed = False
        for receipt in tuple(self._issued.values()):
            try:
                self.cleanup(receipt)
            except UnavailableError:
                failed = True
        if failed:
            raise UnavailableError(
                "one or more RDP launch artifacts could not be removed")

    def start(self, cancellation: Any) -> None:
        cancellation.raise_if_cancelled()

    def stop(self, timeout_seconds: float) -> None:
        del timeout_seconds
        self.cleanup_all()

    def join(self, timeout_seconds: float) -> bool:
        del timeout_seconds
        return not self._issued


__all__ = ["WindowsRdpLauncher"]
