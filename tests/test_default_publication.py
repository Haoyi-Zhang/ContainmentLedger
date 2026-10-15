"""Static default-workflow coverage; never import the POSIX supervisor."""
import ast
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch
import package_audit

ROOT = Path(__file__).resolve().parents[1]


class DefaultPublicationCoverage(unittest.TestCase):
    def check_figure_inventory(self, extra=None, missing=None):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in package_audit.ALLOWED_TOP_LEVEL:
                (root / name).mkdir()
            for name in ('draw_schematics.py', 'late-alias.pdf', 'grouped-cut.pdf'):
                if name != missing:
                    (root / 'figures' / name).write_text('owned inventory fixture', encoding='utf-8')
            if extra:
                (root / 'figures' / extra).write_text('owned unexpected fixture', encoding='utf-8')
            with patch.object(package_audit, 'ROOT', root):
                return package_audit.package_shape_audit()

    def test_exact_manuscript_figure_inventory_is_admitted(self):
        self.assertEqual(self.check_figure_inventory()['python_cache_artifacts'], 0)

    def test_missing_or_extra_manuscript_figure_rejects(self):
        for kwargs in ({'missing': 'late-alias.pdf'}, {'extra': 'old-plot.pdf'}):
            with self.subTest(**kwargs):
                with self.assertRaisesRegex(package_audit.PackageAuditError, 'figure inventory'):
                    self.check_figure_inventory(**kwargs)

    def test_default_checks_include_source_bound_publication_receipt(self):
        tree = ast.parse((ROOT / "reproduce.py").read_text(encoding="utf-8"))
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "execute_part")
        commands = []
        for node in ast.walk(function):
            if isinstance(node, ast.List):
                try:
                    value = ast.literal_eval(node)
                except (ValueError, TypeError):
                    continue
                if value and all(type(part) is str for part in value):
                    commands.append(value)
        expected = ["tests/publication_workflow.py", "--output", "results/publication-workflow"]
        self.assertIn(expected, commands,
                      "default --checks omits complete publication regression/receipt")
        text = (ROOT / "reproduce.py").read_text(encoding="utf-8")
        self.assertIn("'publication-workflow.json'", text)
        self.assertIn("publication_workflow.verify_receipt", text)
        workflow = (ROOT / ".github/workflows/scientific-checks.yml").read_text(encoding="utf-8")
        self.assertIn("reproduce.py --checks", workflow)


if __name__ == "__main__":
    unittest.main()
