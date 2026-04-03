#!/usr/bin/env python3
"""
download_models.py — SecureFlow IDS ML Model Downloader
========================================================
The trained ML model files are too large to host in git (≈930 MB total).
Use this script to download them from your storage bucket before running
the server.

Usage:
    python download_models.py

Configure the download source by setting environment variables or editing
the MODELS dict below.

Supported sources:
  - Local copy    (copy from a network share or USB)
  - HTTP/HTTPS    (direct URL download)
  - AWS S3        (requires: pip install boto3)
  - Google GCS    (requires: pip install google-cloud-storage)
"""

import os
import sys
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────────────────
# Map model filename → download URL (or leave URL empty to skip)
# Set MODEL_BASE_URL env var to a base HTTP URL, or configure a cloud source below.

BASE_DIR = Path(__file__).resolve().parent / "ml_model" / "ai_models" / "models"
MODEL_BASE_URL = os.environ.get("MODEL_BASE_URL", "")  # e.g. https://storage.example.com/models

MODELS = {
    # filename                  : relative URL suffix (appended to MODEL_BASE_URL)
    "rf_new.pkl"               : "rf_new.pkl",
    "iso_forest_new.pkl"       : "iso_forest_new.pkl",
    "iso_scale.pkl"            : "iso_scale.pkl",
    "isolation_forest.pkl"     : "isolation_forest.pkl",
    "xgb.pkl"                  : "xgb.pkl",
    "scaler_xgb.pkl"           : "scaler_xgb.pkl",
    "label_encoder_xgb.pkl"    : "label_encoder_xgb.pkl",
    "scaler_rf_new.pkl"        : "scaler_rf_new.pkl",
    "scaler_iso_new.pkl"       : "scaler_iso_new.pkl",
    # Large legacy models (only needed if you use them):
    # "rf.plk"                 : "rf.plk",       # 380 MB
    # "rf3_bs1.plk"            : "rf3_bs1.plk",  # 438 MB
}


def download_http(url: str, dest: Path) -> None:
    """Download a file over HTTP with a progress indicator."""
    try:
        import urllib.request
        print(f"  Downloading {dest.name} from {url} ...")
        urllib.request.urlretrieve(url, dest)
        size_mb = dest.stat().st_size / 1024 / 1024
        print(f"  ✓ Saved {dest.name} ({size_mb:.1f} MB)")
    except Exception as exc:
        print(f"  ✗ Failed to download {dest.name}: {exc}", file=sys.stderr)


def main() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)

    if not MODEL_BASE_URL:
        print(
            "⚠  MODEL_BASE_URL is not set.\n"
            "   Set the MODEL_BASE_URL environment variable to the base HTTP URL\n"
            "   where your model files are hosted, then re-run this script.\n\n"
            "   Example:\n"
            "     set MODEL_BASE_URL=https://storage.example.com/secureflow-models\n"
            "     python download_models.py\n\n"
            "   Alternatively, manually copy the .pkl/.plk files into:\n"
            f"   {BASE_DIR}\n"
        )
        sys.exit(1)

    print(f"📥 Downloading models to: {BASE_DIR}\n")
    for filename, suffix in MODELS.items():
        dest = BASE_DIR / filename
        if dest.exists():
            size_mb = dest.stat().st_size / 1024 / 1024
            print(f"  ✓ {filename} already exists ({size_mb:.1f} MB) — skipping")
            continue
        url = f"{MODEL_BASE_URL.rstrip('/')}/{suffix}"
        download_http(url, dest)

    print("\n✅ Done. All models are in place.")


if __name__ == "__main__":
    main()
