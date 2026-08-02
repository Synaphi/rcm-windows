from __future__ import annotations

import posixpath
from typing import Iterable


def _canonical_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("path must be a non-empty string")
    if "\x00" in value:
        raise ValueError("path contains a null byte")
    portable = value.replace("\\", "/")
    namespace_path = portable.casefold()
    if (
        portable.startswith("//")
        or namespace_path.startswith("/??/")
        or namespace_path.startswith("/device/")
    ):
        raise ValueError("fake filesystem rejects UNC and namespace paths")
    if not portable.startswith("/"):
        raise ValueError("fake filesystem paths must be absolute")
    normalized = posixpath.normpath(portable)
    return normalized


def _parents(path: str) -> Iterable[str]:
    current = posixpath.dirname(path)
    pending = []
    while current and current != "/":
        pending.append(current)
        current = posixpath.dirname(current)
    yield "/"
    yield from reversed(pending)


class FakeFilesystem:
    def __init__(self) -> None:
        self._directories = {"/"}
        self._files: dict[str, bytes] = {}
        self._events: list[tuple[str, str]] = []

    def _create_parent_directories(self, path: str) -> None:
        parents = tuple(_parents(path))
        for parent in parents:
            if parent in self._files:
                raise NotADirectoryError(parent)
        self._directories.update(parents)

    def mkdir(
        self,
        path: str,
        *,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        canonical = _canonical_path(path)
        if canonical in self._files:
            raise FileExistsError(canonical)
        if canonical in self._directories:
            if exist_ok:
                return
            raise FileExistsError(canonical)
        parent = posixpath.dirname(canonical)
        if parents:
            self._create_parent_directories(canonical)
        elif parent not in self._directories:
            if parent in self._files:
                raise NotADirectoryError(parent)
            raise FileNotFoundError(parent)
        self._directories.add(canonical)
        self._events.append(("mkdir", canonical))

    def write_bytes(
        self,
        path: str,
        data: bytes | bytearray | memoryview,
        *,
        create_parents: bool = False,
    ) -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ValueError("data must be bytes-like")
        canonical = _canonical_path(path)
        if canonical in self._directories:
            raise IsADirectoryError(canonical)
        parent = posixpath.dirname(canonical)
        if create_parents:
            self._create_parent_directories(canonical)
        elif parent not in self._directories:
            if parent in self._files:
                raise NotADirectoryError(parent)
            raise FileNotFoundError(parent)
        self._files[canonical] = bytes(data)
        self._events.append(("write", canonical))

    def write_text(
        self,
        path: str,
        text: str,
        *,
        encoding: str = "utf-8",
        create_parents: bool = False,
    ) -> None:
        self.write_bytes(
            path,
            text.encode(encoding),
            create_parents=create_parents,
        )

    def read_bytes(self, path: str) -> bytes:
        canonical = _canonical_path(path)
        if canonical not in self._files:
            raise FileNotFoundError(canonical)
        self._events.append(("read", canonical))
        return bytes(self._files[canonical])

    def read_text(self, path: str, *, encoding: str = "utf-8") -> str:
        return self.read_bytes(path).decode(encoding)

    def exists(self, path: str) -> bool:
        canonical = _canonical_path(path)
        return canonical in self._directories or canonical in self._files

    def replace(self, source: str, destination: str) -> None:
        source_path = _canonical_path(source)
        destination_path = _canonical_path(destination)
        if source_path not in self._files:
            raise FileNotFoundError(source_path)
        if destination_path in self._directories:
            raise IsADirectoryError(destination_path)
        parent = posixpath.dirname(destination_path)
        if parent not in self._directories:
            if parent in self._files:
                raise NotADirectoryError(parent)
            raise FileNotFoundError(parent)
        self._files[destination_path] = self._files.pop(source_path)
        self._events.append(("replace", f"{source_path}->{destination_path}"))

    def unlink(self, path: str, *, missing_ok: bool = False) -> None:
        canonical = _canonical_path(path)
        if canonical not in self._files:
            if missing_ok:
                return
            raise FileNotFoundError(canonical)
        del self._files[canonical]
        self._events.append(("unlink", canonical))

    def listdir(self, path: str) -> tuple[str, ...]:
        canonical = _canonical_path(path)
        if canonical not in self._directories:
            raise FileNotFoundError(canonical)
        prefix = "/" if canonical == "/" else canonical + "/"
        names = set()
        for candidate in self._directories | set(self._files):
            if candidate.startswith(prefix) and candidate != canonical:
                remainder = candidate[len(prefix) :]
                if remainder:
                    names.add(remainder.split("/", 1)[0])
        self._events.append(("listdir", canonical))
        return tuple(sorted(names))

    def clear(self) -> None:
        self._directories = {"/"}
        self._files.clear()
        self._events.clear()

    def snapshot(self) -> dict[str, object]:
        return {
            "directories": sorted(self._directories),
            "files_hex": {
                path: self._files[path].hex() for path in sorted(self._files)
            },
            "events": [list(event) for event in self._events],
        }

    def resource_count(self) -> int:
        return len(self._files) + max(0, len(self._directories) - 1)
