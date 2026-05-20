#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.


import os
import shutil
import urllib.request
import requests
from pathlib import Path

# Core configuration: Align with your specific feature branch for assets
DB_FILENAME = "omci_knowledge_base.db"
# Hardcoded to your specific GitHub repository and ai-ollama branch raw endpoint
DB_DOWNLOAD_URL = f"https://raw.githubusercontent.com/daneshih1125/omcipcap/ai-ollama/omci_assets/{DB_FILENAME}"

# Standard verified local AI models
EMBED_MODEL = "nomic-embed-text:latest"
LLM_MODEL = "qwen2.5-coder:7b"

OLLAMA_API_URL = "http://localhost:11434/api"


def get_assets_dir():
    """Dynamically resolve the global user-space cache directory (~/.omcipcap/) for assets."""
    # Path.home() automatically resolves to ${HOME} on Linux/WSL2 and C:\Users\Username on Windows
    assets_dir = Path.home() / ".omcipcap"

    # Effectively runs 'mkdir -p ~/.omcipcap' under the hood safely
    assets_dir.mkdir(parents=True, exist_ok=True)

    # Return as standard string type to maintain compatibility with os.path and sqlite3
    return str(assets_dir)


def download_database():
    """Step 1: Download the pre-compiled SQLite vector knowledge base from GitHub."""
    assets_dir = get_assets_dir()
    db_path = os.path.join(assets_dir, DB_FILENAME)

    if os.path.exists(db_path):
        print(f"[+] [Setup] Pre-compiled DB already exists at: {db_path}")
        return True

    print("[*] [Setup] Downloading vector knowledge base from GitHub...")
    print(f"    Source: {DB_DOWNLOAD_URL}")
    try:
        # Using a custom User-Agent header to prevent GitHub from blocking the urllib request
        req = urllib.request.Request(
            DB_DOWNLOAD_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) omcipcap/1.0"
            },
        )
        with urllib.request.urlopen(req) as response, open(db_path, "wb") as out_file:
            shutil.copyfileobj(response, out_file)
        print(f"[+] [Setup] Database successfully deployed to: {db_path}")
        return True
    except Exception as e:
        print(f"[-] [Setup] Failed to download DB: {e}")
        print(
            f"    (Pro-Tip: Please check your network connection or download it manually to {db_path})"
        )
        return False


def check_and_pull_ollama_models():
    """Step 2: Verify local Ollama service availability and automatically pull missing models."""
    print("[*] [Setup] Verifying Ollama service and local models...")

    # 1. Heartbeat check: Ensure Ollama backend daemon is running
    try:
        response = requests.get("http://localhost:11434/", timeout=3)
        if response.status_code != 200:
            raise requests.exceptions.ConnectionError
    except requests.exceptions.ConnectionError:
        print("[-] [Setup] Ollama service is not running!")
        print("    Please start Ollama on your host system first (https://ollama.com).")
        return False

    # 2. Fetch the list of already installed local models
    try:
        tags_response = requests.get(f"{OLLAMA_API_URL}/tags")
        local_models = [m["name"] for m in tags_response.json().get("models", [])]
    except Exception as e:
        print(f"[-] [Setup] Failed to fetch local Ollama models: {e}")
        return False

    # 3. Check and dynamically download required models via Ollama Registry
    required_models = [EMBED_MODEL, LLM_MODEL]
    for model in required_models:
        if model in local_models or model.split(":")[0] in local_models:
            print(f"[+] [Setup] Model '{model}' is installed and ready.")
        else:
            print(
                f"[*] [Setup] Model '{model}' not found. Pulling from Ollama registry (this may take a few minutes)..."
            )
            pull_url = f"{OLLAMA_API_URL}/pull"
            try:
                # stream=False blocks execution until the model download is completely finished
                pull_res = requests.post(
                    pull_url, json={"name": model, "stream": False}
                )
                pull_res.raise_for_status()
                print(f"[+] [Setup] Successfully pulled '{model}'!")
            except Exception as e:
                print(f"[-] [Setup] Failed to pull model '{model}': {e}")
                return False

    return True


def run_ai_setup():
    """Main orchestrator for initializing the omcipcap AI subsystem environment."""
    print("\n" + "=" * 20 + " Starting omcipcap AI Setup " + "=" * 20)

    db_ok = download_database()
    models_ok = check_and_pull_ollama_models()

    print("=" * 68)
    if db_ok and models_ok:
        print("[+] [Success] omcipcap AI subsystem is fully operational!")
        print(
            "    You can now run 'omcipcap ai-overview <pcap_file>' to debug OMCI logs.\n"
        )
    else:
        print("[-] [Failure] AI setup incomplete. Please review the errors above.\n")


if __name__ == "__main__":
    run_ai_setup()
