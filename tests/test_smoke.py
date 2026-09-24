import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("docker"), "Docker is not installed")
class SmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        info = subprocess.run(["docker", "info"], capture_output=True)
        if info.returncode:
            raise unittest.SkipTest("Docker daemon is not running")
        image = subprocess.run(["docker", "image", "inspect", "containmentbench:local"], capture_output=True)
        if image.returncode:
            subprocess.run(["docker", "build", "-t", "containmentbench:local", str(ROOT)], check=True, capture_output=True)

    def run_case(self, scenario):
        with tempfile.TemporaryDirectory() as directory:
            return subprocess.run(
                ["python3", str(ROOT / "run_benchmark.py"), "--skip-build", "--condition", "contained", "--scenario", scenario, "--results-dir", directory],
                cwd=ROOT, capture_output=True, text=True, timeout=60,
            )

    def test_benign_and_adversarial_scenarios(self):
        benign = self.run_case("B01")
        adversarial = self.run_case("A01")
        self.assertEqual(benign.returncode, 0, benign.stderr)
        self.assertEqual(adversarial.returncode, 0, adversarial.stderr)
        self.assertIn("100.0%", benign.stdout)
        self.assertIn("0.0%", adversarial.stdout)

    def test_memory_limit_blocks_pressure(self):
        memory = self.run_case("A11")
        self.assertEqual(memory.returncode, 0, memory.stderr)
        self.assertIn("0.0%", memory.stdout)


if __name__ == "__main__":
    unittest.main()
