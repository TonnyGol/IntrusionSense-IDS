"""CICFlowMeter-style flow features, named as in the CICIDS2017 dataset the models were trained on.

Flow duration is last packet minus first packet, as CICFlowMeter computes it. The previous sniffer
measured up to "now", which stretched flows that were closed by the idle timeout.
"""

import numpy as np

from intrusionsense.flows import Flow

MICROSECONDS = 1_000_000
MIN_DURATION_SECONDS = 0.0001  # keeps the per-second rates finite for single-instant flows


def _stats_or_zero(values: np.ndarray) -> tuple[float, float, float, float]:
    """max, min, mean, std of values, all 0 for an empty array."""
    if len(values) == 0:
        return 0.0, 0.0, 0.0, 0.0
    return float(np.max(values)), float(np.min(values)), float(np.mean(values)), float(np.std(values))


def _gaps_or_zero(timestamps_us: np.ndarray) -> np.ndarray:
    return np.diff(timestamps_us) if len(timestamps_us) > 1 else np.array([0.0])


def _times_or_zero(seconds: list[float]) -> np.ndarray:
    return np.array(seconds) * MICROSECONDS if seconds else np.array([0.0])


def compute_features(flow: Flow) -> dict[str, float]:
    duration = max(flow.last_packet_time - flow.start_time, MIN_DURATION_SECONDS)

    fwd_lens = np.array(flow.fwd_lengths, dtype=np.float64)
    bwd_lens = np.array(flow.bwd_lengths, dtype=np.float64)
    all_lens = np.concatenate([fwd_lens, bwd_lens])

    fwd_ts = np.array(flow.fwd_timestamps) * MICROSECONDS
    bwd_ts = np.array(flow.bwd_timestamps) * MICROSECONDS
    all_ts = np.sort(np.concatenate([fwd_ts, bwd_ts]))

    fwd_iats = _gaps_or_zero(fwd_ts)
    bwd_iats = _gaps_or_zero(bwd_ts)
    all_iats = _gaps_or_zero(all_ts)
    idle_times = _times_or_zero(flow.idle_times)
    active_times = _times_or_zero(flow.active_times)

    fwd_max, fwd_min, fwd_mean, fwd_std = _stats_or_zero(fwd_lens)
    bwd_max, bwd_min, bwd_mean, bwd_std = _stats_or_zero(bwd_lens)

    return {
        "Flow Duration": duration * MICROSECONDS,
        "Total Fwd Packets": len(fwd_lens),
        "Total Length of Fwd Packets": float(np.sum(fwd_lens)),
        "Fwd Packet Length Max": fwd_max,
        "Fwd Packet Length Min": fwd_min,
        "Fwd Packet Length Mean": fwd_mean,
        "Fwd Packet Length Std": fwd_std,
        "Bwd Packet Length Max": bwd_max,
        "Bwd Packet Length Min": bwd_min,
        "Bwd Packet Length Mean": bwd_mean,
        "Bwd Packet Length Std": bwd_std,
        "Flow Bytes/s": float(np.sum(all_lens)) / duration,
        "Flow Packets/s": len(all_lens) / duration,
        "Flow IAT Mean": float(np.mean(all_iats)),
        "Flow IAT Std": float(np.std(all_iats)),
        "Flow IAT Max": float(np.max(all_iats)),
        "Flow IAT Min": float(np.min(all_iats)),
        "Fwd IAT Total": float(np.sum(fwd_iats)),
        "Fwd IAT Mean": float(np.mean(fwd_iats)),
        "Fwd IAT Std": float(np.std(fwd_iats)),
        "Fwd IAT Max": float(np.max(fwd_iats)),
        "Fwd IAT Min": float(np.min(fwd_iats)),
        "Bwd IAT Total": float(np.sum(bwd_iats)),
        "Bwd IAT Mean": float(np.mean(bwd_iats)),
        "Bwd IAT Std": float(np.std(bwd_iats)),
        "Bwd IAT Max": float(np.max(bwd_iats)),
        "Bwd IAT Min": float(np.min(bwd_iats)),
        "Fwd Packets/s": len(fwd_lens) / duration,
        "Bwd Packets/s": len(bwd_lens) / duration,
        "Min Packet Length": float(np.min(all_lens)),
        "Max Packet Length": float(np.max(all_lens)),
        "Packet Length Mean": float(np.mean(all_lens)),
        "Packet Length Std": float(np.std(all_lens)),
        "Packet Length Variance": float(np.var(all_lens)),
        "FIN Flag Count": flow.fin_flag,
        "PSH Flag Count": flow.psh_flag,
        "ACK Flag Count": flow.ack_flag,
        "Average Packet Size": float(np.mean(all_lens)),
        "Subflow Fwd Bytes": float(np.sum(fwd_lens)),
        "act_data_pkt_fwd": flow.act_data_pkt_fwd,
        "Active Mean": float(np.mean(active_times)),
        "Active Max": float(np.max(active_times)),
        "Active Min": float(np.min(active_times)),
        "Idle Mean": float(np.mean(idle_times)),
        "Idle Max": float(np.max(idle_times)),
        "Idle Min": float(np.min(idle_times)),
    }
