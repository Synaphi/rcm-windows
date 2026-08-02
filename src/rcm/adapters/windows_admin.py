"""Fixed-schema Windows implementations for the two local admin actions."""

from __future__ import annotations

from typing import Protocol

from ..local_admin import PrivateFirewallState, RdpHostState
from ..privilege import (
    FirewallRuleState,
    PrivateFirewallApply,
    PrivilegeReceipt,
    PrivilegeRequest,
    PrivilegeStatus,
    PrivilegedOperation,
    RdpHostApply,
)


_RDP_POLICY_PATH = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
_RDP_NLA_PATH = (
    r"SYSTEM\CurrentControlSet\Control\Terminal Server"
    r"\WinStations\RDP-Tcp"
)
_PRIVATE_RULES = (
    ("RayClusterManager-Ray-Private-In", "6379,6380-6385,8265,10001-10100"),
    ("RayClusterManager-LHM-Private-In", "8085"),
    ("RayClusterManager-Control-Private-In", "8866"),
)
_PRIVATE_RULE_OWNER = "RayClusterManager-Private-Inbound-v1"


class RdpRegistry(Protocol):
    def read(self) -> RdpHostState: ...

    def write(self, desired: RdpHostApply) -> None: ...


class PrivateFirewallPolicy(Protocol):
    def read(self) -> PrivateFirewallState: ...

    def write(self, desired: PrivateFirewallApply) -> None: ...


class _WindowsRdpRegistry:
    @staticmethod
    def _value(path: str, name: str) -> int:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            access=winreg.KEY_READ,
        ) as key:
            value, kind = winreg.QueryValueEx(key, name)
        if kind != winreg.REG_DWORD or isinstance(value, bool) or not isinstance(
            value, int
        ):
            raise RuntimeError("RDP policy value has an invalid type")
        return value

    def read(self) -> RdpHostState:
        deny = self._value(_RDP_POLICY_PATH, "fDenyTSConnections")
        nla = self._value(_RDP_NLA_PATH, "UserAuthentication")
        if deny not in (0, 1) or nla not in (0, 1):
            raise RuntimeError("RDP policy value is outside its fixed schema")
        return RdpHostState(enabled=deny == 0, require_nla=nla == 1)

    def write(self, desired: RdpHostApply) -> None:
        import winreg

        values = (
            (
                _RDP_POLICY_PATH,
                "fDenyTSConnections",
                0 if desired.enabled else 1,
            ),
            (
                _RDP_NLA_PATH,
                "UserAuthentication",
                1 if desired.require_nla else 0,
            ),
        )
        for path, name, value in values:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                path,
                access=winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)


class _WindowsPrivateFirewallPolicy:
    """Exact PowerShell cmdlet set executed from the trusted system directory."""

    @staticmethod
    def _executable() -> str:
        import ctypes
        import ntpath
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetSystemDirectoryW.argtypes = (
            wintypes.LPWSTR, wintypes.UINT)
        kernel32.GetSystemDirectoryW.restype = wintypes.UINT
        buffer = ctypes.create_unicode_buffer(32_768)
        length = kernel32.GetSystemDirectoryW(buffer, len(buffer))
        if not 0 < length < len(buffer):
            raise RuntimeError("trusted Windows system directory is unavailable")
        return ntpath.join(
            buffer.value, "WindowsPowerShell", "v1.0", "powershell.exe")

    @classmethod
    def _run(
        cls,
        desired: PrivateFirewallApply | None = None,
    ) -> tuple[str, ...]:
        import ntpath
        import subprocess

        executable = cls._executable()
        module = ntpath.join(
            ntpath.dirname(executable),
            "Modules", "NetSecurity", "NetSecurity.psd1")
        system_root = ntpath.dirname(
            ntpath.dirname(ntpath.dirname(ntpath.dirname(executable))))
        body = (
            cls._read_script()
            if desired is None
            else cls._write_script(desired)
        )
        script = (
            "$ErrorActionPreference='Stop';"
            "Microsoft.PowerShell.Core\\Import-Module -Name '"
            + module.replace("'", "''")
            + "' -Force -ErrorAction Stop;"
            + body
        )
        process = subprocess.run(
            (executable, "-NoLogo", "-NoProfile", "-NonInteractive",
             "-Command", script),
            shell=False, capture_output=True, text=True, timeout=15,
            creationflags=0x08000000,
            env={
                "SystemRoot": system_root,
                "WINDIR": system_root,
                "PSModulePath": ntpath.dirname(module),
            })
        if process.returncode != 0:
            raise RuntimeError("fixed private firewall command failed")
        return tuple(line.strip() for line in process.stdout.splitlines())

    @staticmethod
    def _probe_script(name: str, ports: str) -> str:
        return (
            f"$r=@(NetSecurity\\Get-NetFirewallRule -Name '{name}' -EA SilentlyContinue);"
            "$bad=$r.Count -gt 1;if($r.Count -eq 1){"
            "$p=@($r[0]|NetSecurity\\Get-NetFirewallPortFilter);"
            "$a=@($r[0]|NetSecurity\\Get-NetFirewallAddressFilter);"
            "$x=@($r[0]|NetSecurity\\Get-NetFirewallApplicationFilter);"
            "$s=@($r[0]|NetSecurity\\Get-NetFirewallServiceFilter);"
            f"$bad=$r[0].DisplayName -ne '{name}' -or "
            f"$r[0].Description -ne '{_PRIVATE_RULE_OWNER}' -or "
            f"$r[0].Group -ne '{_PRIVATE_RULE_OWNER}' -or "
            "$r[0].Profile -ne 'Private' -or $r[0].Direction -ne 'Inbound' -or "
            "$r[0].Action -ne 'Allow' -or $r[0].InterfaceType -ne 'Any' -or "
            "$r[0].EdgeTraversalPolicy -ne 'Block' -or $p.Count -ne 1 -or "
            f"$p[0].Protocol -ne 'TCP' -or ($p[0].LocalPort -join ',') -ne '{ports}' -or "
            "$p[0].RemotePort -ne 'Any' -or $a.Count -ne 1 -or "
            "$a[0].LocalAddress -ne 'Any' -or "
            "($a[0].RemoteAddress -join ',') -ne 'LocalSubnet' -or "
            "$x.Count -ne 1 -or $x[0].Program -ne 'Any' -or "
            "$x[0].Package -ne 'Any' -or $s.Count -ne 1 -or "
            "$s[0].Service -ne 'Any'};")

    @staticmethod
    def _read_script() -> str:
        rows = []
        for name, ports in _PRIVATE_RULES:
            rows.append(
                _WindowsPrivateFirewallPolicy._probe_script(name, ports)
                +
                "if($r.Count -eq 0){Write-Output 'absent'}"
                "elseif($bad){Write-Output 'conflict'}"
                "elseif($r[0].Enabled -eq 'True'){"
                "Write-Output 'enabled'}else{Write-Output 'disabled'}}")
        return "$ErrorActionPreference='Stop';" + ";".join(rows)

    @staticmethod
    def _write_script(desired: PrivateFirewallApply) -> str:
        rows = ["$ErrorActionPreference='Stop'"]
        for (name, ports), state in zip(_PRIVATE_RULES, desired.rules, strict=True):
            rows.append(
                _WindowsPrivateFirewallPolicy._probe_script(name, ports)
                +
                "if($bad){throw 'fixed rule ownership conflict'};"
                "if($r.Count -eq 1){$r[0]|"
                "NetSecurity\\Remove-NetFirewallRule -EA Stop}")
            if state is not FirewallRuleState.ABSENT:
                enabled = "$true" if state is FirewallRuleState.ENABLED else "$false"
                rows.append(
                    f"NetSecurity\\New-NetFirewallRule -Name '{name}' "
                    f"-DisplayName '{name}' "
                    f"-Description '{_PRIVATE_RULE_OWNER}' "
                    f"-Group '{_PRIVATE_RULE_OWNER}' "
                    "-Profile Private -Direction Inbound -Action Allow "
                    f"-Protocol TCP -LocalPort {ports} "
                    "-RemotePort Any -LocalAddress Any -RemoteAddress LocalSubnet "
                    "-Program Any -Service Any -InterfaceType Any "
                    f"-EdgeTraversalPolicy Block -Enabled {enabled}|Out-Null")
        return ";".join(rows)

    def read(self) -> PrivateFirewallState:
        raw = self._run()
        try:
            states = tuple(FirewallRuleState(value) for value in raw)
        except ValueError:
            raise RuntimeError("a private firewall rule conflicts with fixed schema")
        if len(states) != len(_PRIVATE_RULES):
            raise RuntimeError("private firewall observation is incomplete")
        return PrivateFirewallState(states)

    def write(self, desired: PrivateFirewallApply) -> None:
        self._run(desired)


class WindowsAdminObserver:
    def __init__(
        self,
        *,
        rdp: RdpRegistry | None = None,
        firewall: PrivateFirewallPolicy | None = None,
    ) -> None:
        self._rdp = rdp or _WindowsRdpRegistry()
        self._firewall = firewall or _WindowsPrivateFirewallPolicy()

    def rdp_host_state(self) -> RdpHostState:
        return self._rdp.read()

    def private_firewall_state(self) -> PrivateFirewallState:
        return self._firewall.read()


class WindowsAdminApplier:
    """Elevated-helper dispatcher with exactly two typed semantic branches."""

    def __init__(
        self,
        *,
        rdp: RdpRegistry | None = None,
        firewall: PrivateFirewallPolicy | None = None,
    ) -> None:
        self._rdp = rdp or _WindowsRdpRegistry()
        self._firewall = firewall or _WindowsPrivateFirewallPolicy()

    def apply(self, request: PrivilegeRequest) -> PrivilegeReceipt:
        if not isinstance(request, PrivilegeRequest):
            raise TypeError("request must be a PrivilegeRequest")
        before: RdpHostState | PrivateFirewallState | None = None
        try:
            before = self._read(request.operation)
            self._write(request)
            after = self._read(request.operation)
            desired = self._desired_state(request)
            if after != desired:
                raise RuntimeError("local admin verification failed")
        except Exception:
            restored = self._restore(request.operation, before)
            return PrivilegeReceipt(
                request.request_id,
                request.operation,
                PrivilegeStatus.FAILED,
                (
                    "local_admin.apply_failed"
                    if restored
                    else "local_admin.rollback_failed"
                ),
                changed=not restored,
            )
        return PrivilegeReceipt(
            request.request_id,
            request.operation,
            PrivilegeStatus.SUCCEEDED,
            "local_admin.applied",
            changed=before != after,
            verified=True,
        )

    def _restore(
        self,
        operation: PrivilegedOperation,
        before: RdpHostState | PrivateFirewallState | None,
    ) -> bool:
        if before is None:
            return False
        try:
            if operation is PrivilegedOperation.RDP_HOST_APPLY:
                assert isinstance(before, RdpHostState)
                self._rdp.write(before.as_apply())
                return self._rdp.read() == before
            assert isinstance(before, PrivateFirewallState)
            self._firewall.write(before.as_apply())
            return self._firewall.read() == before
        except Exception:
            return False

    def _read(
        self,
        operation: PrivilegedOperation,
    ) -> RdpHostState | PrivateFirewallState:
        if operation is PrivilegedOperation.RDP_HOST_APPLY:
            return self._rdp.read()
        return self._firewall.read()

    def _write(self, request: PrivilegeRequest) -> None:
        if request.operation is PrivilegedOperation.RDP_HOST_APPLY:
            assert isinstance(request.arguments, RdpHostApply)
            self._rdp.write(request.arguments)
            return
        assert isinstance(request.arguments, PrivateFirewallApply)
        self._firewall.write(request.arguments)

    @staticmethod
    def _desired_state(
        request: PrivilegeRequest,
    ) -> RdpHostState | PrivateFirewallState:
        if isinstance(request.arguments, RdpHostApply):
            return RdpHostState(
                request.arguments.enabled,
                request.arguments.require_nla,
            )
        return PrivateFirewallState(request.arguments.rules)


__all__ = [
    "PrivateFirewallPolicy",
    "RdpRegistry",
    "WindowsAdminApplier",
    "WindowsAdminObserver",
]
