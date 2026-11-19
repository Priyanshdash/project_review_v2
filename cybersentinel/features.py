r"""Feature extraction, log parsing, and temporal encoding for CyberSentinel-LLM.
Implements Equations (1)-(5) from the research paper:
- Drain-based template extraction and parameter extraction
- Sinusoidal temporal encoding: \psi_{temp}(t_i)
- Multi-modal feature fusion for log sequences and network flows
"""

from __future__ import annotations
import math
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer


def drain_extract_template(log_message: str) -> str:
    """Extract a structural template by masking dynamic parameters (IPs, Block IDs, hex, numbers).
    Follows Section 4.2 Drain-based abstraction.
    """
    msg = log_message.strip()
    # Mask IPs
    msg = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', '<*IP*>', msg)
    # Mask Block IDs
    msg = re.sub(r'blk_-?\d+', '<*BLK*>', msg)
    # Mask Hex addresses
    msg = re.sub(r'0x[0-9a-fA-F]+', '<*HEX*>', msg)
    # Mask Numbers
    msg = re.sub(r'\b\d+\b', '<*NUM*>', msg)
    # Normalize whitespaces
    msg = re.sub(r'\s+', ' ', msg)
    return msg


def sinusoidal_temporal_encoding(timestamps: list[float] | np.ndarray, d_t: int = 16) -> np.ndarray:
    r"""Computes sinusoidal temporal encoding \psi_{temp}(t_i) as defined in Eq. (3):
    \psi_{temp}(t_i) = [sin(t_i / \omega_k), cos(t_i / \omega_k)]_{k=1}^{d_t/2}
    with \omega_k = 10000^{2k / d_t}
    """
    t = np.array(timestamps, dtype=np.float32).reshape(-1, 1)
    # Normalize timestamps to [0, 1] if not already
    t_min, t_max = t.min(), t.max()
    if t_max > t_min:
        t_norm = (t - t_min) / (t_max - t_min)
    else:
        t_norm = np.zeros_like(t)

    half_dim = d_t // 2
    encodings = []
    for k in range(1, half_dim + 1):
        omega_k = 10000.0 ** (2.0 * k / d_t)
        encodings.append(np.sin(t_norm / omega_k))
        encodings.append(np.cos(t_norm / omega_k))

    return np.hstack(encodings)


def extract_flow_features(flow_dict: dict, d_proto: int = 4) -> np.ndarray:
    r"""Extracts flow-level representation f_j = [b_in, b_out, n_pkt, \Delta t, h_proto]
    as defined in Eq. (4).
    """
    b_in = float(flow_dict.get("bytes_in", 0))
    b_out = float(flow_dict.get("bytes_out", 0))
    n_pkt = float(flow_dict.get("packet_count", 0))
    dt = float(flow_dict.get("duration", 0.0))
    proto = str(flow_dict.get("protocol", "TCP")).upper()

    proto_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
    h_proto = [0.0] * d_proto
    idx = proto_map.get(proto, 3)
    if idx < d_proto:
        h_proto[idx] = 1.0

    return np.array([b_in, b_out, n_pkt, dt] + h_proto, dtype=np.float32)


class LogFeatureExtractor:
    """Unified Feature Extractor combining TF-IDF log representation,
    Drain template representations, and temporal encodings.
    """

    def __init__(self, max_features: int = 500, d_t: int = 16):
        self.vectorizer = TfidfVectorizer(
            max_features=max_features,
            token_pattern=r'(?u)\b\w+\b',
            ngram_range=(1, 2)
        )
        self.d_t = d_t
        self.is_fitted = False

    def fit(self, texts: list[str]) -> LogFeatureExtractor:
        templates = [drain_extract_template(t) for t in texts]
        self.vectorizer.fit(templates)
        self.is_fitted = True
        return self

    def transform(self, texts: list[str], timestamps: list[float] | None = None) -> np.ndarray:
        if not self.is_fitted:
            raise RuntimeError("LogFeatureExtractor must be fitted before transform.")
        templates = [drain_extract_template(t) for t in texts]
        text_features = self.vectorizer.transform(templates).toarray()

        if timestamps is not None and len(timestamps) == len(texts):
            temp_features = sinusoidal_temporal_encoding(timestamps, d_t=self.d_t)
        else:
            # Default zero temporal encodings to preserve feature dimensions
            temp_features = np.zeros((len(texts), self.d_t), dtype=np.float32)

        return np.hstack([text_features, temp_features])

    def fit_transform(self, texts: list[str], timestamps: list[float] | None = None) -> np.ndarray:
        self.fit(texts)
        return self.transform(texts, timestamps)
