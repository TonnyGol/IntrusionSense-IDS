import csv
from pathlib import Path

from intrusionsense.features import FEATURE_NAMES
from intrusionsense.records import FlowRecord

LABEL_COLUMN = "Attack Type"
NORMAL_LABEL = "Normal Traffic"


class CsvRecorder:
    """Takes the uploader's place: appends each flow's features to a CSV as a labelled training row.

    Rows come from the sensor's own feature code, so a model trained on them sees what it will see live.
    """

    def __init__(self, path: str | Path, label: str = NORMAL_LABEL):
        self.label = label
        self.records_sent = 0
        self.records_dropped = 0
        path = Path(path)
        is_new = not path.exists() or path.stat().st_size == 0
        self._file = path.open("a", newline="")
        self._writer = csv.writer(self._file)
        if is_new:
            self._writer.writerow([*FEATURE_NAMES, LABEL_COLUMN])

    def __len__(self) -> int:
        return 0  # nothing is ever buffered

    def enqueue(self, record_json: str) -> None:
        record = FlowRecord.model_validate_json(record_json)
        self._writer.writerow([record.features[name] for name in FEATURE_NAMES] + [self.label])
        self.records_sent += 1

    def close(self) -> None:
        self._file.close()
