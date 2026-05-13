import os
import subprocess


def test_generic(console):
    subprocess.run(["sudo", "usbrelay", "HURTM_1=0"], check=True)
    console.expect(os.environ["EXPECTED_STRING"], timeout=int(os.environ.get("TEST_TIMEOUT", 60)))
