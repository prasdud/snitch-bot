# aggregates multiple packages.json files to remove duplicates and create a master_packages.json file
import json
from pathlib import Path
import pandas as pd

# constants
BASE_DIR = Path(__file__).resolve().parents[1] / 'output'
files = [
    '1-packages.json',
    '2-packages.json',
    '3-packages.json',
]

# core
def read_all_packages():
    all_packages = []
    for file in files:
        try:
            packages = json.loads((BASE_DIR / file).read_text())
        except FileNotFoundError:
            print(f"[aggregator] ERROR: {file} not found")
            return []
        except json.JSONDecodeError as e:
            print(f"[aggregator] ERROR: Failed to parse {file}: {e}")
            return []

        if not isinstance(packages, list):
            print(f"[aggregator] ERROR: {file} does not contain a JSON array")
            return []

        all_packages.extend(packages)
        print(f"[aggregator] Loaded {len(packages)} packages from {file}")

    return all_packages

# main
if __name__ == '__main__':
    master_json = read_all_packages()

    if not master_json:
        print('[aggregator] No packages to aggregate')
        raise SystemExit(1)

    data_frame = pd.DataFrame(master_json)

    if not {'name', 'version'}.issubset(data_frame.columns):
        print("[aggregator] ERROR: Expected keys 'name' and 'version' in package records")
        raise SystemExit(1)

    unique_data_frame = data_frame.drop_duplicates(subset=['name', 'version'])
    dropped = len(data_frame) - len(unique_data_frame)
    print(f'[aggregator] Dropped {dropped} duplicate entries')
    print(f'[aggregator] Aggregation done, unique packages: {len(unique_data_frame)}')
    unique_data_frame.to_json(BASE_DIR / 'unique_master.json', orient='records', indent=2)