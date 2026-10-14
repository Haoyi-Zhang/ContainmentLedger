"""Static default-workflow coverage; never import the POSIX supervisor."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DefaultPublicationCoverage(unittest.TestCase):
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
