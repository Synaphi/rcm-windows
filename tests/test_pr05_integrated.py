from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from rcm.config import (
    Config,
    ConfigStore,
    Node,
    NodesSection,
    canonical_config_bytes,
    parse_config_bytes,
)


def synthetic_config(count: int) -> Config:
    nodes = tuple(
        Node(
            node_id=f"synthetic-node-{index:02d}",
            address=f"192.0.2.{index + 1}",
            role="worker",
            enabled=True,
            cpu_count=(index % 16) + 1,
        )
        for index in range(count)
    )
    return Config(
        nodes=NodesSection(
            items=nodes,
            local_node_id=nodes[0].node_id,
        )
    )


class PR05IntegratedTests(unittest.TestCase):
    def test_synthetic_1_8_32_node_configs_are_three_run_deterministic(
        self,
    ) -> None:
        for count in (1, 8, 32):
            with self.subTest(count=count):
                config = synthetic_config(count)
                canonical_runs = [canonical_config_bytes(config) for _ in range(3)]
                self.assertEqual(1, len(set(canonical_runs)))
                self.assertEqual(
                    config,
                    parse_config_bytes(canonical_runs[0]),
                )
                stored_runs: list[bytes] = []
                checksums: list[str] = []
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    for run in range(3):
                        destination = root / f"run-{run}" / "config.json"
                        stored = ConfigStore(destination).save(
                            config,
                            expected_generation=0,
                        )
                        loaded = ConfigStore(destination).load(
                            require_existing=True
                        )
                        self.assertEqual(config, loaded.config)
                        self.assertEqual(1, loaded.generation)
                        self.assertEqual(stored, loaded)
                        stored_runs.append(destination.read_bytes())
                        checksums.append(
                            hashlib.sha256(destination.read_bytes()).hexdigest()
                        )
                        residue = [
                            path.name
                            for path in destination.parent.iterdir()
                            if path.name.endswith(
                                (".tmp", ".journal", ".journal.tmp")
                            )
                        ]
                        self.assertEqual([], residue)
                        self.assertTrue(
                            destination.with_name("config.json.lock").is_file()
                        )
                self.assertEqual(1, len(set(stored_runs)))
                self.assertEqual(1, len(set(checksums)))

    def test_copy_convert_input_is_never_used_as_store_destination(self) -> None:
        fixture = (
            Path(__file__).parent / "fixtures" / "v1_schema_corpus.json"
        )
        before = fixture.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "config.json"
            ConfigStore(destination).save(synthetic_config(8))
            self.assertNotEqual(fixture.resolve(), destination.resolve())
        self.assertEqual(before, fixture.read_bytes())


if __name__ == "__main__":
    unittest.main()
