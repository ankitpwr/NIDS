#!/usr/bin/env python3
"""Flask ML service for batch-trained network attack prediction.

This service is designed for your current architecture:
Agent -> Node.js backend -> Flask ML service -> Prediction

It loads the batch-trained artifacts produced by the Kaggle/GitHub-style
pipeline and exposes:
  - GET  /
  - GET  /health
  - POST /predict
  - POST /debug/ae        (live AutoEncoder reconstruction debug)
  - POST /debug/preprocess (inspect preprocessing output)

Expected artifacts (inside ./artifacts/):
  - preprocessor.pkl
  - ae.pt
  - orc.npz
  - rf.pkl
  - training_metadata.json

The service is tolerant of your current payload shape. It accepts either:
  - raw UNSW-style fields (proto/service/state/etc.), or
  - your current approximate fields (proto_encoded/service_encoded/state_encoded,
    swin_encoded/trans_depth_encoded, etc.) and maps them to something usable.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import joblib
import numpy as np
import torch
from flask import Flask, jsonify, request

from modules.ae import AEConfig, AEWrapper
from modules.data_preprocessing import DataPreprocessor
from modules.orc_selector import ORCConfig, ORCFeatureSelector
from modules.sklearn_wrapper import SklearnWrapper
# ----------------------------------------------------------------------------
# Paths / config
# ----------------------------------------------------------------------------
BASE_DIR = Path(os.getenv("ML_BASE_DIR", ".")).resolve()
ARTIFACTS_DIR = Path(os.getenv("ML_ARTIFACTS_DIR", BASE_DIR / "artifacts")).resolve()

PREPROCESSOR_PATH = Path(os.getenv("ML_PREPROCESSOR_PATH", ARTIFACTS_DIR / "preprocessor.pkl"))
AE_PATH = Path(os.getenv("ML_AE_PATH", ARTIFACTS_DIR / "ae.pt"))
ORC_PATH = Path(os.getenv("ML_ORC_PATH", ARTIFACTS_DIR / "orc.npz"))
RF_PATH = Path(os.getenv("ML_RF_PATH", ARTIFACTS_DIR / "rf.pkl"))
METADATA_PATH = Path(os.getenv("ML_METADATA_PATH", ARTIFACTS_DIR / "training_metadata.json"))

HOST = os.getenv("ML_HOST", "0.0.0.0")
PORT = int(os.getenv("ML_PORT", "3002"))
DEBUG = os.getenv("ML_DEBUG", "false").lower() == "true"

DEFAULT_THRESHOLD = float(os.getenv("ML_ATTACK_THRESHOLD", "0.5"))

# Raw-feature names used by the GitHub-style preprocessor/model pipeline.
# These are the names the Flask service prefers to work with internally.
RAW_FEATURE_ORDER = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "sjit",
    "djit",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "response_body_len",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "proto",
    "service",
    "state",
    "swin",
    "trans_depth",
]

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ml_service")


@dataclass
class ModelBundle:
    preprocessor: Optional[DataPreprocessor]
    ae: Optional[AEWrapper]
    orc: Optional[ORCFeatureSelector]
    rf: Any
    threshold: float
    apply_feature_selection: bool
    feature_names: List[str]
    selected_indices: Optional[np.ndarray]
    selected_feature_names: List[str]
    processed_feature_count: int


BUNDLE: Optional[ModelBundle] = None


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json_file(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Could not read {path}: {e}")
        return None


def safe_joblib_load(path: Path):
    if not path.exists():
        return None
    return joblib.load(path)


def infer_threshold(metadata: dict) -> float:
    try:
        return float(
            metadata["training_stats"]["optimized_attack_threshold"]
        )
    except Exception:
        try:
            return float(metadata["model_config"]["sgd_classifier"]["attack_threshold"])
        except Exception:
            return DEFAULT_THRESHOLD


def load_or_build_preprocessor() -> Optional[DataPreprocessor]:
    if not PREPROCESSOR_PATH.exists():
        return None
    try:
        return DataPreprocessor.load(str(PREPROCESSOR_PATH))
    except Exception as e:
        logger.warning(f"Failed loading preprocessor: {e}")
        return None


def load_or_build_ae(processed_feature_count: int, metadata: dict) -> Optional[AEWrapper]:
    if not AE_PATH.exists():
        return None

    try:
        ae_cfg = metadata.get("model_config", {}).get("ae", {})
        wrapper = AEWrapper(
            AEConfig(
                d_in=processed_feature_count,
                d_hidden=int(ae_cfg.get("d_hidden", 32)),
                lr=float(ae_cfg.get("lr", 1e-4)),
            )
        )
        wrapper.load(str(AE_PATH))
        return wrapper
    except Exception as e:
        logger.warning(f"Failed loading AE: {e}")
        return None


def load_or_build_orc(processed_feature_count: int, feature_names: List[str], metadata: dict) -> Optional[ORCFeatureSelector]:
    if not ORC_PATH.exists():
        return None

    try:
        orc_cfg = metadata.get("model_config", {}).get("orc", {})
        wrapper = ORCFeatureSelector.load(
            str(ORC_PATH),
            ORCConfig(
                beta=float(orc_cfg.get("beta", 0.8)),
                top_k=int(orc_cfg.get("top_k", 30)),
                update_every=int(orc_cfg.get("update_every", 500)),
                lock_after_samples=int(orc_cfg.get("lock_after_samples", 100)),
            ),
            training_mode="batch",
        )
        # Defensive: if artifact is older/different, make sure feature names align.
        if len(wrapper.feature_names) != processed_feature_count and feature_names:
            logger.warning(
                "ORC feature count does not match processed feature count; continuing with loaded artifact."
            )
        return wrapper
    except Exception as e:
        logger.warning(f"Failed loading ORC selector: {e}")
        return None


def load_or_build_rf():
    if not RF_PATH.exists():
        raise FileNotFoundError(f"Classifier artifact not found: {RF_PATH}")
    try:
        # Works when your wrapper exposes a classmethod load.
        return SklearnWrapper.load(str(RF_PATH))
    except Exception:
        # Fallback for plain sklearn pickle/joblib.
        try:
            return joblib.load(RF_PATH)
        except Exception as e:
            raise RuntimeError(f"Could not load classifier artifact: {e}")


def map_protocol(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, str):
        v = value.lower().strip()
        if v in {"tcp", "udp", "icmp"}:
            return v
        if v.isdigit():
            return {"6": "tcp", "17": "udp", "1": "icmp"}.get(v, v)
        return v
    try:
        iv = int(value)
        return {6: "tcp", 17: "udp", 1: "icmp"}.get(iv, str(iv))
    except Exception:
        return str(value)


def map_service(raw: Dict[str, Any]) -> str:
    # Prefer an already-provided raw service value.
    if isinstance(raw.get("service"), str):
        return raw["service"]

    # Fall back to your current service heuristics.
    port = raw.get("dst_port", raw.get("dstport", raw.get("dport", None)))
    try:
        port = int(port)
    except Exception:
        port = None

    if port == 80 or port == 8080:
        return "http"
    if port == 443:
        return "https"
    if port == 53:
        return "dns"
    return "unknown"


def map_state(raw: Dict[str, Any]) -> str:
    if isinstance(raw.get("state"), str):
        return raw["state"]

    # Fall back from your current encoded/derived values.
    if "connection_state" in raw:
        v = str(raw["connection_state"]).upper()
        if v in {"CON", "FIN", "INT"}:
            return v

    state_encoded = raw.get("state_encoded")
    try:
        state_encoded = int(state_encoded)
    except Exception:
        state_encoded = None

    if state_encoded == 2:
        return "FIN"
    if state_encoded == 1:
        return "CON"
    return "INT"


def normalize_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Convert agent payload to the raw shape expected by the preprocessor."""
    out: Dict[str, Any] = {}
 
    def pick(*names, default=0):
        for name in names:
            if name in raw and raw[name] is not None:
                return raw[name]
        return default
 
    # ── Numeric flow fields ───────────────────────────────────────────────────
    out["dur"]               = float(pick("dur", "duration",                  default=0.0))
    out["spkts"]             = float(pick("spkts", "forward_packets",         default=0.0))
    out["dpkts"]             = float(pick("dpkts", "reverse_packets",         default=0.0))
    out["sbytes"]            = float(pick("sbytes", "forward_bytes",          default=0.0))
    out["dbytes"]            = float(pick("dbytes", "reverse_bytes",          default=0.0))
    out["rate"]              = float(pick("rate", "packets_per_second",       default=0.0))
 
    # TTL — src and dst
    out["sttl"]              = float(pick("sttl", "forward_ttl",              default=0.0))
    out["dttl"]              = float(pick("dttl", "reverse_ttl",              default=0.0))  # FIX
 
    # Throughput
    out["sload"]             = float(pick("sload",                            default=0.0))
    out["dload"]             = float(pick("dload",                            default=0.0))
 
    # Losses
    out["sloss"]             = float(pick("sloss",                            default=0.0))
    out["dloss"]             = float(pick("dloss",                            default=0.0))
 
    # Inter-packet timing — src and dst
    out["sinpkt"]            = float(pick("sinpkt", "forward_interarrival",   default=0.0))
    out["dinpkt"]            = float(pick("dinpkt", "reverse_interarrival",   default=0.0))  # FIX
 
    # Jitter
    out["sjit"]              = float(pick("sjit",                             default=0.0))
    out["djit"]              = float(pick("djit",                             default=0.0))
 
    # TCP base sequence numbers
    out["stcpb"]             = float(pick("stcpb",                            default=0.0))  # FIX
    out["dtcpb"]             = float(pick("dtcpb",                            default=0.0))  # FIX
 
    # RTT breakdown
    out["tcprtt"]            = float(pick("tcprtt",                           default=0.0))
    out["synack"]            = float(pick("synack",                           default=0.0))
    out["ackdat"]            = float(pick("ackdat",                           default=0.0))
 
    # Packet size means
    out["smean"]             = float(pick("smean",                            default=0.0))
    out["dmean"]             = float(pick("dmean",                            default=0.0))
 
    # HTTP
    out["response_body_len"] = float(pick("response_body_len",                default=0.0))
 
    # Connection-table counters
    out["ct_state_ttl"]      = float(pick("ct_state_ttl",                    default=0.0))
    out["ct_dst_ltm"]        = float(pick("ct_dst_ltm",                      default=0.0))
    out["ct_src_dport_ltm"]  = float(pick("ct_src_dport_ltm",                default=0.0))
    out["ct_dst_sport_ltm"]  = float(pick("ct_dst_sport_ltm",                default=0.0))
    out["ct_dst_src_ltm"]    = float(pick("ct_dst_src_ltm",                  default=0.0))
    out["ct_flw_http_mthd"]  = float(pick("ct_flw_http_mthd",                default=0.0))
    out["ct_src_ltm"]        = float(pick("ct_src_ltm",                      default=0.0))
    out["ct_srv_src"]        = float(pick("ct_srv_src",                      default=0.0))  # FIX
    out["ct_srv_dst"]        = float(pick("ct_srv_dst",                      default=0.0))  # FIX
 
    # Window / depth
    out["swin"]              = float(pick("swin", "swin_encoded",             default=0.0))
    out["trans_depth"]       = float(pick("trans_depth", "trans_depth_encoded", default=0.0))
 
    # ── Categorical fields ────────────────────────────────────────────────────
    out["proto"]   = map_protocol(pick("proto", "protocol", "proto_encoded",  default=None))
    out["service"] = map_service(raw)
    out["state"]   = map_state(raw)
 
    # ── Metadata (logging only, stripped before model) ────────────────────────
    out["srcip"] = pick("srcip", "source_ip", default="unknown")
    out["_meta"] = {
        "src_ip":   pick("srcip", "source_ip",   default="unknown"),
        "dst_ip":   pick("dstip", "dst_ip",       default="unknown"),
        "src_port": pick("src_port",              default=0),
        "dst_port": pick("dst_port",              default=0),
        "protocol": pick("proto", "protocol", "proto_encoded", default=0),
    }
    return out
 

def feature_names_from_preprocessor(preprocessor: DataPreprocessor) -> List[str]:
    try:
        return preprocessor.get_feature_names()
    except Exception:
        info = preprocessor.get_feature_info()
        return list(info.get("output_feature_names", []))


def build_bundle() -> ModelBundle:
    metadata = read_json_file(METADATA_PATH) or {}

    preprocessor = load_or_build_preprocessor()
    if preprocessor is None:
        raise FileNotFoundError(
            f"Missing preprocessor artifact: {PREPROCESSOR_PATH}. You need artifacts from training."
        )

    feature_names = feature_names_from_preprocessor(preprocessor)
    processed_feature_count = len(feature_names)
    threshold = infer_threshold(metadata)
    apply_feature_selection = bool(metadata.get("apply_feature_selection", True))

    ae = load_or_build_ae(processed_feature_count, metadata)
    orc = load_or_build_orc(processed_feature_count, feature_names, metadata) if apply_feature_selection else None
    rf = load_or_build_rf()

    selected_indices = None
    selected_feature_names: List[str] = []
    if orc is not None:
        try:
            selected_indices = orc.get_mask_indices()
            selected_feature_names = orc.get_mask_names()
        except Exception:
            selected_indices = None
            selected_feature_names = []

    logger.info(f"Loaded preprocessor from {PREPROCESSOR_PATH}")
    logger.info(f"Loaded AE: {'yes' if ae is not None else 'no'}")
    logger.info(f"Loaded ORC: {'yes' if orc is not None else 'no'}")
    logger.info(f"Loaded classifier from {RF_PATH}")
    logger.info(f"Feature selection enabled: {apply_feature_selection}")
    logger.info(f"Attack threshold: {threshold}")

    return ModelBundle(
        preprocessor=preprocessor,
        ae=ae,
        orc=orc,
        rf=rf,
        threshold=threshold,
        apply_feature_selection=apply_feature_selection,
        feature_names=feature_names,
        selected_indices=selected_indices,
        selected_feature_names=selected_feature_names,
        processed_feature_count=processed_feature_count,
    )


def get_bundle() -> ModelBundle:
    global BUNDLE
    if BUNDLE is None:
        BUNDLE = build_bundle()
    return BUNDLE


def vector_to_dict(vector: np.ndarray, names: Sequence[str]) -> Dict[str, float]:
    return {name: float(vector[i]) for i, name in enumerate(names)}


def predict_probability(model: Any, x_dict: Dict[str, float], threshold: float) -> Tuple[int, float]:
    """Return (prediction, attack_probability)."""
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(x_dict)
        if isinstance(proba, dict):
            attack_prob = float(proba.get(1, proba.get("1", 0.0)))
        elif isinstance(proba, np.ndarray):
            if proba.ndim == 2 and proba.shape[1] >= 2:
                attack_prob = float(proba[0, 1])
            else:
                attack_prob = float(proba.ravel()[-1])
        else:
            # try generic indexing
            attack_prob = float(proba[0][1])
    else:
        pred = model.predict(x_dict)
        if isinstance(pred, (list, np.ndarray)):
            attack_prob = float(pred[0])
        else:
            attack_prob = float(pred)

    prediction = 1 if attack_prob >= threshold else 0
    return prediction, attack_prob


def preprocess_sample(bundle: ModelBundle, payload: Dict[str, Any]) -> Tuple[np.ndarray, Dict[str, Any], Dict[str, Any]]:
    normalized = normalize_payload(payload)
    x_processed = bundle.preprocessor.transform_single(normalized)
    processed_names = bundle.feature_names
    processed_dict = vector_to_dict(x_processed, processed_names)
    return x_processed, processed_dict, normalized


def build_classifier_input(bundle: ModelBundle, processed_dict: Dict[str, float]) -> Dict[str, float]:
    if not bundle.apply_feature_selection or bundle.orc is None:
        return processed_dict

    try:
        indices = bundle.selected_indices if bundle.selected_indices is not None else bundle.orc.get_mask_indices()
        names = bundle.selected_feature_names if bundle.selected_feature_names else bundle.orc.get_mask_names()
        return {name: float(processed_dict[name]) for name in names if name in processed_dict}
    except Exception:
        return processed_dict


def ae_debug_summary(bundle: ModelBundle, x_processed: np.ndarray, processed_names: Sequence[str]) -> Dict[str, Any]:
    if bundle.ae is None:
        return {"available": False, "reason": "AE artifact not loaded"}

    with torch.no_grad():
        tensor = torch.from_numpy(x_processed.astype(np.float32))
        recon = bundle.ae.forward_no_grad(tensor).numpy()

    abs_err = np.abs(x_processed - recon)
    top_idx = np.argsort(-abs_err)[: min(10, len(abs_err))]

    top_errors = [
        {
            "feature": processed_names[i],
            "original": float(x_processed[i]),
            "reconstructed": float(recon[i]),
            "abs_error": float(abs_err[i]),
        }
        for i in top_idx
    ]

    return {
        "available": True,
        "reconstruction_error_mean": float(abs_err.mean()),
        "reconstruction_error_max": float(abs_err.max()),
        "reconstruction_error_sum": float(abs_err.sum()),
        "top_errors": top_errors,
        "reconstructed_vector": recon.tolist(),
    }


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@app.get("/")
def root():
    b = get_bundle()
    return jsonify(
        {
            "service": "ML Attack Predictor",
            "status": "running",
            "mode": "batch-trained",
            "endpoints": ["/health", "/predict", "/debug/ae", "/debug/preprocess"],
            "feature_count": b.processed_feature_count,
            "apply_feature_selection": b.apply_feature_selection,
            "threshold": b.threshold,
        }
    )


@app.get("/health")
def health():
    b = get_bundle()
    return jsonify(
        {
            "status": "healthy",
            "timestamp": utc_now_iso(),
            "preprocessor_loaded": b.preprocessor is not None,
            "ae_loaded": b.ae is not None,
            "orc_loaded": b.orc is not None,
            "classifier_loaded": b.rf is not None,
            "feature_selection_enabled": b.apply_feature_selection,
            "feature_count": b.processed_feature_count,
            "threshold": b.threshold,
            "artifacts_dir": str(ARTIFACTS_DIR),
        }
    )


@app.post("/predict")
def predict():
    try:
        b = get_bundle()
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Request body must be a JSON object"}), 400

        x_processed, processed_dict, normalized = preprocess_sample(b, payload)
        x_for_classifier = build_classifier_input(b, processed_dict)

        prediction, attack_prob = predict_probability(b.rf, x_for_classifier, b.threshold)
        label = "🚨 ATTACK" if prediction == 1 else "✅ NORMAL"
        print(
         f"[PREDICT] {label} | "
         f"prob={attack_prob:.3f} | "
          f"src={normalized.get('srcip','?')} | "
          f"spkts={payload.get('spkts','?')} sbytes={payload.get('sbytes','?')}"
          )

        response = {
            "timestamp": utc_now_iso(),
            "prediction": prediction,
            "attack_probability": attack_prob,
            "source_ip": normalized.get("srcip", "unknown"),
            "feature_selection_enabled": b.apply_feature_selection,
            "feature_count": len(x_for_classifier),
            "features_used": list(x_for_classifier.keys()),
        }

        # Optional debug flag: /predict?debug_ae=1
        debug_ae = str(request.args.get("debug_ae", "0")).lower() in {"1", "true", "yes"}
        if debug_ae:
            response["ae_debug"] = ae_debug_summary(b, x_processed, b.feature_names)

        return jsonify(response)

    except Exception as e:
        logger.exception("Error in /predict")
        return jsonify({"error": str(e)}), 500


@app.post("/debug/ae")
def debug_ae():
    try:
        b = get_bundle()
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Request body must be a JSON object"}), 400

        x_processed, processed_dict, normalized = preprocess_sample(b, payload)
        summary = ae_debug_summary(b, x_processed, b.feature_names)

        return jsonify(
            {
                "timestamp": utc_now_iso(),
                "source_ip": normalized.get("srcip", "unknown"),
                "processed_feature_count": len(processed_dict),
                "ae_debug": summary,
            }
        )
    except Exception as e:
        logger.exception("Error in /debug/ae")
        return jsonify({"error": str(e)}), 500


@app.post("/debug/preprocess")
def debug_preprocess():
    try:
        b = get_bundle()
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Request body must be a JSON object"}), 400

        x_processed, processed_dict, normalized = preprocess_sample(b, payload)

        return jsonify(
            {
                "timestamp": utc_now_iso(),
                "source_ip": normalized.get("srcip", "unknown"),
                "normalized_input": normalized,
                "processed_feature_count": len(processed_dict),
                "processed_feature_names": b.feature_names,
                "processed_vector": x_processed.tolist(),
                "processed_dict_preview": dict(list(processed_dict.items())[:10]),
                "feature_selection_enabled": b.apply_feature_selection,
                "selected_feature_names": b.selected_feature_names,
            }
        )
    except Exception as e:
        logger.exception("Error in /debug/preprocess")
        return jsonify({"error": str(e)}), 500


# ----------------------------------------------------------------------------
# Startup
# ----------------------------------------------------------------------------
try:
    BUNDLE = build_bundle()
except Exception as e:
    logger.error(f"Initial model load failed: {e}")
    BUNDLE = None


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
