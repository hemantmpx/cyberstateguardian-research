from __future__ import annotations

import unittest

from experiments.analyze_service_install_object_drop_pilot import _items


class PowerShellCollectionUnwrapTests(unittest.TestCase):
    def test_unwraps_serialized_collection_wrapper(self) -> None:
        self.assertEqual(_items({"Count": 2, "value": ["a", "b"]}), ["a", "b"])

    def test_preserves_plain_list_and_empty_values(self) -> None:
        self.assertEqual(_items([1, 2]), [1, 2])
        self.assertEqual(_items(None), [])


if __name__ == "__main__":
    unittest.main()
