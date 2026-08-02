"""Isolated tests for windows_credentials; no real account/store mutations."""

import ctypes
import json
import re
import sys

import windows_credentials as wc


class FakeLocalPasswordChangeApi:
    def __init__(self):
        self.calls = []

    def change_password(self, computer, username, old_password, new_password):
        self.calls.append((computer, username, old_password, new_password))


class FakeCredentialStoreApi:
    def __init__(self):
        self.entries = {}
        self.write_calls = []
        self.delete_calls = []

    def write_credential(self, target, username, password):
        self.write_calls.append((target, username, password))
        self.entries[target] = username

    def credential_exists(self, target):
        return target in self.entries

    def credential_matches_username(self, target, username):
        stored = self.entries.get(target)
        return (stored is not None
                and stored.casefold() == username.casefold())

    def delete_credential(self, target):
        self.delete_calls.append(target)
        existed = target in self.entries
        self.entries.pop(target, None)
        return existed


def raises(expected, callback):
    try:
        callback()
    except expected as exc:
        return exc
    raise AssertionError(f"expected {expected.__name__}")


def test_normalize_local_account():
    for spec in ("SYNTHETIC_USER_D", ".\\SYNTHETIC_USER_D", "SYNTHETIC_NODE_D\\SYNTHETIC_USER_D", "synthetic_node_d\\SYNTHETIC_USER_D"):
        account = wc.normalize_local_account(spec, local_computer="SYNTHETIC_NODE_D")
        assert account.computer == "SYNTHETIC_NODE_D"
        assert account.username == "SYNTHETIC_USER_D"
        assert account.qualified_name == "SYNTHETIC_NODE_D\\SYNTHETIC_USER_D"


def test_reject_non_local_accounts():
    rejected = (
        "MicrosoftAccount\\owner@example.com",
        "AzureAD\\owner@example.com",
        "EntraID\\owner",
        "owner@example.com",
        "OTHER-SYNTHETIC_PC\\SYNTHETIC_USER_D",
        "DOMAIN\\group\\user",
        "bad/user",
        "bad,user",
        "",
    )
    for spec in rejected:
        raises(
            wc.AccountValidationError,
            lambda spec=spec: wc.normalize_local_account(spec, local_computer="SYNTHETIC_NODE_D"),
        )


def test_normal_password_change_uses_old_password_and_local_server():
    api = FakeLocalPasswordChangeApi()
    old_secret = "synthetic-test-old-password-7"
    new_secret = "synthetic-test-new-password-8"
    result = wc.change_local_account_password(
        r"SYNTHETIC_NODE_D\SYNTHETIC_USER_D", old_secret, new_secret,
        local_computer="SYNTHETIC_NODE_D", api=api)
    assert result is None
    assert api.calls == [("SYNTHETIC_NODE_D", "SYNTHETIC_USER_D", old_secret, new_secret)]

    seen = []
    native = wc.Win32LocalPasswordChangeApi(
        net_user_change_password=lambda server, username, old, new:
            seen.append((server, username)) or 0)
    native.change_password("SYNTHETIC_NODE_D", "SYNTHETIC_USER_D", old_secret, new_secret)
    assert seen == [(r"\\SYNTHETIC_NODE_D", "SYNTHETIC_USER_D")]

    failing = wc.Win32LocalPasswordChangeApi(
        net_user_change_password=lambda server, username, old, new: 86)
    exc = raises(
        wc.WindowsSecurityError,
        lambda: failing.change_password(
            "SYNTHETIC_NODE_D", "SYNTHETIC_USER_D", old_secret, new_secret))
    assert old_secret not in str(exc) and new_secret not in str(exc)


def test_rdp_target_normalization():
    assert wc.normalize_rdp_target("192.0.2.25") == "TERMSRV/192.0.2.25"
    assert wc.normalize_rdp_target("termsrv/192.0.2.25") == "TERMSRV/192.0.2.25"
    assert wc.normalize_rdp_target("2001:0db8::1") == "TERMSRV/2001:db8::1"
    for invalid in (
        "LEGACY_NODE",
        "https://192.0.2.25",
        "192.000.002.025",
        "192.0.2.999",
        "",
    ):
        raises(wc.CredentialValidationError, lambda invalid=invalid: wc.normalize_rdp_target(invalid))


def test_rdp_store_operations_use_injected_api_only():
    api = FakeCredentialStoreApi()
    secret = "synthetic-test-store-password-8"
    assert wc.write_rdp_credential(
        "192.0.2.25", "LEGACY_NODE\\SYNTHETIC_USER_D", secret, api=api
    ) is None
    assert api.write_calls == [("TERMSRV/192.0.2.25", "LEGACY_NODE\\SYNTHETIC_USER_D", secret)]
    assert wc.rdp_credential_exists("192.0.2.25", api=api) is True
    assert wc.rdp_credential_matches(
        "192.0.2.25", "legacy_node\\synthetic_user_d", api=api) is True
    assert wc.rdp_credential_matches(
        "192.0.2.25", "MicrosoftAccount\\owner@example.com", api=api
    ) is False
    assert wc.delete_rdp_credential("192.0.2.25", api=api) is True
    assert wc.rdp_credential_exists("192.0.2.25", api=api) is False
    assert wc.delete_rdp_credential("192.0.2.25", api=api) is False


def test_native_credential_boundary_uses_only_injected_callables():
    seen = []
    last_error = {"value": 1168}

    def cred_write(credential_pointer, flags):
        credential = ctypes.cast(
            credential_pointer, ctypes.POINTER(wc._CREDENTIALW)
        ).contents
        seen.append(
            (
                "write",
                credential.TargetName,
                credential.UserName,
                credential.Type,
                credential.Persist,
                credential.CredentialBlobSize,
                flags,
            )
        )
        return 1

    def cred_read(target, credential_type, flags, output_pointer):
        seen.append(("read", target, credential_type, flags))
        return 0

    def cred_delete(target, credential_type, flags):
        seen.append(("delete", target, credential_type, flags))
        return 0

    def cred_free(pointer):
        seen.append(("free",))

    api = wc.Win32CredentialStoreApi(
        cred_write=cred_write,
        cred_read=cred_read,
        cred_delete=cred_delete,
        cred_free=cred_free,
        get_last_error=lambda: last_error["value"],
    )
    secret = "synthetic-test-native-password-5"
    assert api.write_credential("TERMSRV/192.0.2.25", "LEGACY_NODE\\SYNTHETIC_USER_D", secret) is None
    assert seen[0][:5] == (
        "write",
        "TERMSRV/192.0.2.25",
        "LEGACY_NODE\\SYNTHETIC_USER_D",
        2,
        2,
    )
    assert secret not in repr(seen)
    assert api.credential_exists("TERMSRV/192.0.2.25") is False
    assert api.credential_matches_username(
        "TERMSRV/192.0.2.25", "LEGACY_NODE\\SYNTHETIC_USER_D") is False
    assert api.delete_credential("TERMSRV/192.0.2.25") is False
    assert not any(call[0] == "free" for call in seen)

    saved = wc._CREDENTIALW()
    saved.UserName = r"SYNTHETIC_NODE_G\SYNTHETIC_USER_G"
    saved_pointer = ctypes.pointer(saved)

    def cred_read_saved(target, credential_type, flags, output_pointer):
        seen.append(("read-saved", target, credential_type, flags))
        ctypes.cast(
            output_pointer, ctypes.POINTER(wc._PCREDENTIALW)
        )[0] = saved_pointer
        return 1

    matching = wc.Win32CredentialStoreApi(
        cred_write=cred_write,
        cred_read=cred_read_saved,
        cred_delete=cred_delete,
        cred_free=cred_free,
        get_last_error=lambda: 0,
    )
    assert matching.credential_matches_username(
        "TERMSRV/192.0.2.24", r"synthetic_node_g\synthetic_user_g") is True
    assert matching.credential_matches_username(
        "TERMSRV/192.0.2.24",
        r"MicrosoftAccount\synthetic-account@example.com") is False
    assert [call[0] for call in seen].count("free") == 2

    failing = wc.Win32CredentialStoreApi(
        cred_write=lambda credential_pointer, flags: 0,
        cred_read=cred_read,
        cred_delete=cred_delete,
        cred_free=cred_free,
        get_last_error=lambda: 5,
    )
    exc = raises(
        wc.WindowsSecurityError,
        lambda: failing.write_credential(
            "TERMSRV/192.0.2.25", "LEGACY_NODE\\SYNTHETIC_USER_D", secret
        ),
    )
    assert secret not in str(exc)


def test_generated_password_policy():
    generated = {wc.generate_strong_password() for _ in range(64)}
    assert len(generated) == 64
    for password in generated:
        assert len(password) == 24
        assert password.isascii()
        assert re.search(r"[A-Z]", password)
        assert re.search(r"[a-z]", password)
        assert re.search(r"[0-9]", password)
        assert re.search(r"[!#$%+\-.:=?@_~]", password)
        assert not re.search(r"[\s'\"`\\]", password)
    for invalid_length in (True, 15, 129, 24.0):
        raises(ValueError, lambda value=invalid_length: wc.generate_strong_password(value))


def test_password_validation_does_not_echo_secret():
    secret = "X" * 257
    exc = raises(
        wc.CredentialValidationError,
        lambda: wc.write_rdp_credential(
            "192.0.2.25", "LEGACY_NODE\\SYNTHETIC_USER_D", secret, api=FakeCredentialStoreApi()
        ),
    )
    assert secret not in str(exc)


def test_module_has_no_reset_command_or_logging_path():
    source = open(wc.__file__, encoding="utf-8").read()
    forbidden = (
        "NetUserSetInfo",
        "_USER_INFO_1003",
        "set_local_account_password",
        "Win32LocalAccountApi",
        "LocalAccountApi",
        "import subprocess",
        "from subprocess",
        "import logging",
        "print(",
    )
    for needle in forbidden:
        assert needle not in source
    assert "set_local_account_password" not in wc.__all__
    assert "Win32LocalAccountApi" not in wc.__all__
    assert not hasattr(wc, "set_local_account_password")
    assert not hasattr(wc, "Win32LocalAccountApi")


def main():
    tests = [
        test_normalize_local_account,
        test_reject_non_local_accounts,
        test_normal_password_change_uses_old_password_and_local_server,
        test_rdp_target_normalization,
        test_rdp_store_operations_use_injected_api_only,
        test_native_credential_boundary_uses_only_injected_callables,
        test_generated_password_policy,
        test_password_validation_does_not_echo_secret,
        test_module_has_no_reset_command_or_logging_path,
    ]
    results = []
    failed = 0
    for test in tests:
        try:
            test()
            results.append({"test": test.__name__, "ok": True})
        except Exception as exc:
            failed += 1
            results.append({"test": test.__name__, "ok": False, "error": str(exc)})
    print(json.dumps({"suite": "windows_credentials", "passed": len(tests) - failed,
                      "failed": failed, "results": results}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
