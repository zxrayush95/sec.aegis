#!/usr/bin/env python3
"""
Aegis Security Rules Packaging & Verification Tool
"""
import os
import sys
import json
import hashlib
import base64

def compute_sha256(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def update_manifest(manifest_path: str, pkg_path: str, sig_path: str, version: int = 2):
    pkg_hash = compute_sha256(pkg_path)
    sig_content = ""
    if os.path.exists(sig_path):
        with open(sig_path, "r", encoding="utf-8") as f:
            sig_content = f.read().strip()

    manifest_data = {
        "version": version,
        "minSdkVersion": 24,
        "applicationId": "com.aegis.sample",
        "packageUrl": f"https://raw.githubusercontent.com/zxrayush95/sec.aegis/main/rules/rules-v{version}.pkg",
        "packageSha256": pkg_hash,
        "rulesCount": 1,
        "timestamp": int(os.path.getmtime(pkg_path) * 1000),
        "signature": sig_content
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)
    print(f"Manifest updated -> {manifest_path} (SHA-256: {pkg_hash})")

if __name__ == "__main__":
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    manifest = os.path.join(base_dir, "manifest.json")
    pkg = os.path.join(base_dir, "rules", "rules-v2.pkg")
    sig = os.path.join(base_dir, "signatures", "rules-v2.sig")
    if os.path.exists(pkg):
        update_manifest(manifest, pkg, sig, version=2)
    else:
        print(f"Package not found: {pkg}")
