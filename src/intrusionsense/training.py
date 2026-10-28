"""Train the two-stage model from the raw CICIDS2017 day files (plus optional recorded normal traffic)."""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from intrusionsense.features import FEATURE_NAMES, MODEL_FEATURES
from intrusionsense.labels import ATTACK_LABELS
from intrusionsense.recorder import LABEL_COLUMN, NORMAL_LABEL

log = logging.getLogger(__name__)

DAY_COLUMN = "Day"
COUNT_COLUMN = "Count"  # how many identical flows this row stands for
UNKNOWN_DAY = "unknown"  # the cleaned dataset has no day information
RAW_LABEL_COLUMN = "Label"
SEED = 42
RAW_FILE_ENCODING = "latin-1"  # one web-attack label contains a byte that is not valid UTF-8
# Layer 1 sample sizes of the original notebooks: keeps normal and suspicious traffic roughly balanced
LAYER_1_NORMAL_ROWS = 30_000
LAYER_1_SUSPICIOUS_ROWS = 58_785
LAYER_1_MAX_DEPTH = 15
LAYER_2_TREES = 100
LAYER_2_MAX_DEPTH = 20
TRAIN_DAYS = ("monday", "tuesday", "wednesday")  # held-out-day evaluation trains on these
METADATA_FILE = "metadata.json"
MODEL_FILES = ("layer1_model.pkl", "layer1_features.pkl", "layer2_model.pkl", "layer2_features.pkl")

# CICIDS2017 label -> our class. Infiltration (36 flows) is left out: too few to learn from.
CLASS_BY_RAW_LABEL = {
    "BENIGN": NORMAL_LABEL,
    "Bot": "Bots",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "DDoS": "DDoS",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "Heartbleed": "DoS",
    "PortScan": "Port Scanning",
}
WEB_ATTACK_PREFIX = "Web Attack"
CLASS_ID_BY_NAME = {name: class_id for class_id, name in ATTACK_LABELS.items()}
KNOWN_CLASSES = {NORMAL_LABEL, *CLASS_ID_BY_NAME}


@dataclass
class Dataset:
    frame: pd.DataFrame  # FEATURE_NAMES, LABEL_COLUMN and DAY_COLUMN
    rows_read: int = 0
    rows_invalid: int = 0
    rows_unmapped: int = 0
    duplicates_removed: int = 0
    notes: list[str] = field(default_factory=list)


def class_for_raw_label(raw_label: str) -> str | None:
    label = raw_label.strip()
    if label.startswith(WEB_ATTACK_PREFIX):
        return "Web Attacks"
    return CLASS_BY_RAW_LABEL.get(label)


def day_of_file(path: Path) -> str:
    return path.name.split("-")[0].strip().lower()


def _read_dataset_file(path: Path) -> pd.DataFrame:
    """One CSV with FEATURE_NAMES, LABEL_COLUMN (mapped to our classes, None if unusable) and DAY_COLUMN.

    Two layouts are accepted: the raw CICIDS2017 day files (a `Label` column, one file per day) and the
    "cleaned" single file that already has our `Attack Type` classes but no day information.
    """
    header = [c.strip() for c in pd.read_csv(path, encoding=RAW_FILE_ENCODING, nrows=0).columns]
    is_cleaned = LABEL_COLUMN in header
    label_column = LABEL_COLUMN if is_cleaned else RAW_LABEL_COLUMN
    wanted = set(FEATURE_NAMES) | {label_column}
    part = pd.read_csv(
        path,
        encoding=RAW_FILE_ENCODING,
        usecols=lambda c: c.strip() in wanted,
        dtype={c: np.float32 for c in FEATURE_NAMES},
    )
    part.columns = [c.strip() for c in part.columns]
    labels = part.pop(label_column)
    part[LABEL_COLUMN] = (
        labels.map(lambda v: v if v in KNOWN_CLASSES else None)
        if is_cleaned
        else labels.map(class_for_raw_label)
    )
    part[DAY_COLUMN] = UNKNOWN_DAY if is_cleaned else day_of_file(path)
    return part


def load_cicids(raw_dir: Path) -> Dataset:
    """Read every file, keep the 46 features, drop invalid rows and exact duplicates."""
    files = sorted(Path(raw_dir).glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files in {raw_dir}")
    parts = []
    for path in files:
        parts.append(_read_dataset_file(path))
        log.info("Read %s: %d rows", path.name, len(parts[-1]))
    return _clean(pd.concat(parts, ignore_index=True))


def _clean(frame: pd.DataFrame) -> Dataset:
    dataset = Dataset(frame=frame, rows_read=len(frame))
    dataset.rows_unmapped = int(frame[LABEL_COLUMN].isna().sum())
    frame = frame.dropna(subset=[LABEL_COLUMN])

    features = frame[list(FEATURE_NAMES)]
    valid = np.isfinite(features.to_numpy()).all(axis=1)
    dataset.rows_invalid = int((~valid).sum())
    frame = frame[valid]

    before = len(frame)
    # Identical flows collapse to one row so a test flow never also appears in training, but the row keeps
    # its number of copies: common traffic must keep its weight or the model forgets what usual looks like.
    row_hash = pd.util.hash_pandas_object(frame[[*FEATURE_NAMES, LABEL_COLUMN]], index=False)
    frame = frame.assign(**{COUNT_COLUMN: row_hash.map(row_hash.value_counts())})
    frame = frame.loc[~row_hash.duplicated()]
    dataset.duplicates_removed = before - len(frame)
    dataset.frame = frame.reset_index(drop=True)
    return dataset


def load_recordings(recordings_dir: Path | None) -> pd.DataFrame:
    """Flows saved by `intrusionsense record`: live-pipeline features, labelled by the recorder."""
    columns = [*FEATURE_NAMES, LABEL_COLUMN]
    files = sorted(Path(recordings_dir).glob("*.csv")) if recordings_dir else []
    if not files:
        return pd.DataFrame(columns=columns)
    frame = pd.concat([pd.read_csv(path)[columns] for path in files], ignore_index=True)
    frame = frame[np.isfinite(frame[list(FEATURE_NAMES)].to_numpy()).all(axis=1)]
    return frame.drop_duplicates()


def layer_1_training_frame(cicids: pd.DataFrame, recordings: pd.DataFrame, seed: int = SEED) -> pd.DataFrame:
    """Balanced normal/suspicious sample of CICIDS2017 drawn by frequency, plus every recorded flow."""
    is_normal = cicids[LABEL_COLUMN] == NORMAL_LABEL
    normal = cicids[is_normal]
    suspicious = cicids[~is_normal]
    # drawing with replacement in proportion to Count reproduces sampling the original, duplicated data
    sample = [
        normal.sample(n=LAYER_1_NORMAL_ROWS, random_state=seed, weights=COUNT_COLUMN, replace=True),
        suspicious.sample(n=LAYER_1_SUSPICIOUS_ROWS, random_state=seed, weights=COUNT_COLUMN, replace=True),
        recordings,
    ]
    return pd.concat([part[[*FEATURE_NAMES, LABEL_COLUMN]] for part in sample], ignore_index=True)


def fit_layer_1(frame: pd.DataFrame, seed: int = SEED) -> DecisionTreeClassifier:
    suspicious = (frame[LABEL_COLUMN] != NORMAL_LABEL).astype(int)
    model = DecisionTreeClassifier(max_depth=LAYER_1_MAX_DEPTH, random_state=seed)
    return model.fit(frame[list(MODEL_FEATURES)].to_numpy(), suspicious)


def fit_layer_2(frame: pd.DataFrame, seed: int = SEED) -> RandomForestClassifier:
    attacks = frame[frame[LABEL_COLUMN] != NORMAL_LABEL]
    classes = attacks[LABEL_COLUMN].map(CLASS_ID_BY_NAME)
    weights = attacks[COUNT_COLUMN].to_numpy(dtype=float)
    # "balanced" class weights computed on the frequency-weighted class sizes, not on the collapsed rows
    class_totals = pd.Series(weights).groupby(classes.to_numpy()).sum()
    class_weight = {int(c): weights.sum() / (len(class_totals) * total) for c, total in class_totals.items()}
    model = RandomForestClassifier(
        n_estimators=LAYER_2_TREES,
        max_depth=LAYER_2_MAX_DEPTH,
        class_weight=class_weight,
        random_state=seed,
        n_jobs=-1,
    )
    return model.fit(attacks[list(MODEL_FEATURES)].to_numpy(), classes.to_numpy(), sample_weight=weights)


def save_models(layer_1, layer_2, out_dir: Path, details: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(layer_1, out_dir / "layer1_model.pkl")
    joblib.dump(list(MODEL_FEATURES), out_dir / "layer1_features.pkl")
    joblib.dump(layer_2, out_dir / "layer2_model.pkl")
    joblib.dump(list(MODEL_FEATURES), out_dir / "layer2_features.pkl")
    metadata = {
        "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "scikit_learn": sklearn.__version__,
        "seed": SEED,
        "sha256": {name: hashlib.sha256((out_dir / name).read_bytes()).hexdigest() for name in MODEL_FILES},
        **details,
    }
    (out_dir / METADATA_FILE).write_text(json.dumps(metadata, indent=2) + "\n")


def train(raw_dir: Path, recordings_dir: Path | None, out_dir: Path) -> dict:
    dataset = load_cicids(raw_dir)
    recordings = load_recordings(recordings_dir)
    log.info(
        "CICIDS2017: %d rows read, %d invalid, %d unmapped, %d duplicates removed, %d kept",
        dataset.rows_read,
        dataset.rows_invalid,
        dataset.rows_unmapped,
        dataset.duplicates_removed,
        len(dataset.frame),
    )
    layer_1 = fit_layer_1(layer_1_training_frame(dataset.frame, recordings))
    layer_2 = fit_layer_2(dataset.frame)
    details = {
        "rows_read": dataset.rows_read,
        "rows_invalid": dataset.rows_invalid,
        "rows_unmapped": dataset.rows_unmapped,
        "duplicates_removed": dataset.duplicates_removed,
        "rows_kept": len(dataset.frame),
        "recorded_normal_flows": len(recordings),
        "classes": dataset.frame[LABEL_COLUMN].value_counts().to_dict(),
    }
    save_models(layer_1, layer_2, out_dir, details)
    return details
