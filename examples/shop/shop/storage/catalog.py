import json
from pathlib import Path

DEFAULT = {"apple": 1.25, "pear": 0.80}


def load_catalog():
    path = Path(__file__).with_name("catalog.json")
    if path.exists():
        return json.loads(path.read_text())
    return dict(DEFAULT)
