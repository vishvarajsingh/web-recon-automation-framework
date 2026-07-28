import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import main


def test_parse_target_domain():
    parsed = main.normalize_target('example.com')
    assert parsed['valid'] is True
    assert parsed['hostname'] == 'example.com'


def test_run_creates_outputs(tmp_path):
    target = 'example.com'
    parsed = main.normalize_target(target)
    payload = main.collect_recon(target)
    assert payload['normalized_target']['hostname'] == 'example.com'
    json.dumps(payload)


if __name__ == '__main__':
    test_parse_target_domain()
    test_run_creates_outputs(tempfile.mkdtemp())
    print('Basic framework tests passed')
