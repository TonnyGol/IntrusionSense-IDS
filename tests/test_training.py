import json

import numpy as np
import pandas as pd
import pytest

from intrusionsense.engine import IDSEngine
from intrusionsense.evaluation import build_report
from intrusionsense.features import FEATURE_NAMES
from intrusionsense.labels import ATTACK_LABELS
from intrusionsense.recorder import LABEL_COLUMN
from intrusionsense.training import (
    METADATA_FILE,
    MODEL_FILES,
    class_for_raw_label,
    day_of_file,
    load_cicids,
    train,
)

ROWS_PER_LABEL = 60
DAYS = {
    "Monday-WorkingHours.pcap_ISCX.csv": ["BENIGN"],
    "Tuesday-WorkingHours.pcap_ISCX.csv": ["BENIGN", "FTP-Patator", "SSH-Patator"],
    "Wednesday-workingHours.pcap_ISCX.csv": ["BENIGN", "DoS Hulk", "Heartbleed"],
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": ["BENIGN", "Web Attack \x96 XSS", "Bot"],
    "Friday-WorkingHours-Afternoon.pcap_ISCX.csv": ["BENIGN", "PortScan", "DDoS", "Infiltration"],
}
LABEL_OFFSET = {
    label: i
    for i, label in enumerate(
        [
            "BENIGN",
            "FTP-Patator",
            "SSH-Patator",
            "DoS Hulk",
            "Heartbleed",
            "Web Attack \x96 XSS",
            "Bot",
            "PortScan",
            "DDoS",
            "Infiltration",
        ]
    )
}


def write_day(path, labels, seed):
    """A CICIDS-shaped CSV: spaced column names, extra columns, one Label; classes are well separated."""
    rng = np.random.default_rng(seed)
    frames = []
    for label in labels:
        values = rng.normal(LABEL_OFFSET[label] * 20, 1.0, size=(ROWS_PER_LABEL, len(FEATURE_NAMES)))
        frames.append(pd.DataFrame(values, columns=[f" {n}" for n in FEATURE_NAMES]).assign(Label=label))
    day = pd.concat(frames, ignore_index=True)
    day[" Destination Port"] = 80
    day[" Fwd Header Length"] = 20
    day.to_csv(path, index=False, encoding="latin-1")
    return day


@pytest.fixture
def raw_dir(tmp_path):
    directory = tmp_path / "raw"
    directory.mkdir()
    for i, (name, labels) in enumerate(DAYS.items()):
        write_day(directory / name, labels, seed=i)
    return directory


def test_raw_labels_map_onto_our_six_classes():
    assert class_for_raw_label("BENIGN") == "Normal Traffic"
    assert class_for_raw_label("DoS slowloris") == "DoS"
    assert class_for_raw_label("SSH-Patator") == "Brute Force"
    assert class_for_raw_label("Web Attack \x96 Sql Injection") == "Web Attacks"
    assert class_for_raw_label("Infiltration") is None
    assert day_of_file(__import__("pathlib").Path("Thursday-WorkingHours-Morning.csv")) == "thursday"


def test_loading_cleans_maps_labels_and_reports_what_it_dropped(raw_dir):
    friday = raw_dir / "Friday-WorkingHours-Afternoon.pcap_ISCX.csv"
    day = pd.read_csv(friday, encoding="latin-1")
    day.loc[0, " Flow Duration"] = np.inf  # one invalid row
    day = pd.concat([day, day.iloc[[5]]])  # one exact duplicate
    day.to_csv(friday, index=False, encoding="latin-1")

    dataset = load_cicids(raw_dir)

    assert dataset.rows_unmapped == ROWS_PER_LABEL  # Infiltration
    assert dataset.rows_invalid == 1
    assert dataset.duplicates_removed == 1
    assert list(dataset.frame.columns[:46]) == list(FEATURE_NAMES)
    assert set(dataset.frame[LABEL_COLUMN]) == {
        "Normal Traffic",
        "Brute Force",
        "DoS",
        "Web Attacks",
        "Bots",
        "Port Scanning",
        "DDoS",
    }
    assert "Infiltration" not in set(dataset.frame[LABEL_COLUMN])


def test_missing_data_folder_is_a_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_cicids(tmp_path)


def test_training_writes_models_the_engine_can_load_and_use(raw_dir, tmp_path):
    out = tmp_path / "models"

    details = train(raw_dir, recordings_dir=None, out_dir=out)

    assert all((out / name).exists() for name in MODEL_FILES)
    metadata = json.loads((out / METADATA_FILE).read_text())
    assert metadata["rows_kept"] == details["rows_kept"]
    assert set(metadata["sha256"]) == set(MODEL_FILES)

    engine = IDSEngine(out, l1_threshold=0.5)
    assert list(engine.l2_model.classes_) == sorted(ATTACK_LABELS)  # ids line up with ATTACK_LABELS
    ddos_like = {name: LABEL_OFFSET["DDoS"] * 20.0 for name in FEATURE_NAMES}
    normal_like = {name: 0.0 for name in FEATURE_NAMES}
    assert engine.predict(ddos_like).label == "DDoS"
    assert not engine.predict(normal_like).is_threat


def test_recorded_normal_traffic_joins_layer_1_training(raw_dir, tmp_path):
    recordings = tmp_path / "rec"
    recordings.mkdir()
    rows = pd.DataFrame(np.full((40, len(FEATURE_NAMES)), 7.0), columns=list(FEATURE_NAMES))
    rows.assign(**{LABEL_COLUMN: "Normal Traffic"}).to_csv(recordings / "mine.csv", index=False)

    details = train(raw_dir, recordings_dir=recordings, out_dir=tmp_path / "models")

    assert details["recorded_normal_flows"] == 1  # identical rows collapse to one


def test_the_evaluation_report_is_complete_and_reproducible(raw_dir):
    first = build_report(raw_dir, recordings_dir=None)
    second = build_report(raw_dir, recordings_dir=None)

    assert first == second
    for heading in (
        "exact duplicate flows collapsed",
        "Layer 1: normal or suspicious",
        "Layer 2: which attack",
        "Confusion matrix",
        "days it never saw",
        "do not show",
    ):
        assert heading in first
    assert "| Port Scanning flagged |" in first


def test_the_cleaned_single_file_layout_loads_and_skips_the_held_out_day_test(tmp_path):
    rng = np.random.default_rng(3)
    frames = []
    for label in (
        "Normal Traffic",
        "DoS",
        "DDoS",
        "Brute Force",
        "Bots",
        "Web Attacks",
        "Port Scanning",
        "Mystery",
    ):
        values = rng.normal(len(frames) * 20, 1.0, size=(ROWS_PER_LABEL, len(FEATURE_NAMES)))
        frames.append(pd.DataFrame(values, columns=list(FEATURE_NAMES)).assign(**{"Attack Type": label}))
    directory = tmp_path / "cleaned"
    directory.mkdir()
    pd.concat(frames).assign(**{"Destination Port": 80}).to_csv(
        directory / "cicids2017_cleaned.csv", index=False
    )

    dataset = load_cicids(directory)

    assert dataset.rows_unmapped == ROWS_PER_LABEL  # the label we do not know is dropped, not guessed
    assert set(dataset.frame["Day"]) == {"unknown"}
    report = build_report(directory, recordings_dir=None)
    assert "does not say which day" in report


def test_duplicates_collapse_but_keep_their_count_so_common_traffic_keeps_its_weight(raw_dir):
    friday = raw_dir / "Friday-WorkingHours-Afternoon.pcap_ISCX.csv"
    day = pd.read_csv(friday, encoding="latin-1")
    day = pd.concat([day, day.iloc[[5]], day.iloc[[5]]])  # the same flow three times in all
    day.to_csv(friday, index=False, encoding="latin-1")

    dataset = load_cicids(raw_dir)

    assert dataset.duplicates_removed == 2
    assert dataset.frame["Count"].max() == 3
    assert dataset.frame["Count"].sum() == dataset.rows_read - dataset.rows_unmapped


def test_models_do_not_learn_from_tcp_flag_counts(raw_dir, tmp_path):
    from intrusionsense.features import FLAG_FEATURES

    train(raw_dir, recordings_dir=None, out_dir=tmp_path / "models")

    engine = IDSEngine(tmp_path / "models", l1_threshold=0.5)
    assert not set(FLAG_FEATURES) & set(engine.l1_features)
    assert not set(FLAG_FEATURES) & set(engine.l2_features)
    assert len(engine.l1_features) == 43


def test_report_measures_false_alarms_on_held_out_recorded_traffic(raw_dir, tmp_path):
    recordings = tmp_path / "rec"
    recordings.mkdir()
    rng = np.random.default_rng(9)
    for name, rows in (("big.csv", 300), ("tiny.csv", 20)):
        values = rng.normal(0, 1.0, size=(rows, len(FEATURE_NAMES)))
        pd.DataFrame(values, columns=list(FEATURE_NAMES)).assign(**{LABEL_COLUMN: "Normal Traffic"}).to_csv(
            recordings / name, index=False
        )

    report = build_report(raw_dir, recordings_dir=recordings)

    assert "Layer 1 on recorded normal traffic" in report
    assert "| big.csv | 90 |" in report  # 30% of 300 kept out of training
    assert "| tiny.csv | 6 | too few flows to measure |" in report
