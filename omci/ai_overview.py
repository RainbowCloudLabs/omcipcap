#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih daneshih1125@gmail.com
# Licensed under the MIT License.

import json
import os
import sys
import requests
from omci.overview import generate_pcap_ai_overview_data

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
# DEFAULT_MODEL = "anthropic/claude-3.5-sonnet"
DEFAULT_MODEL = "anthropic/claude-sonnet-4-5"

SYSTEM_PROMPT = """You are an expert in GPON/XGS-PON OMCI protocol (ITU-T G.988).
You will analyze a structured JSON overview of a complete ONU registration and provisioning capture.

The input contains these sections:
- onu_capability: ONU hardware capability (PON type, T-CONT count, queue count, UNI ports)
- check_summary: Packet health check — failed responses, late responses, TID duplicates, vendor ME packets
- mib_database: Full MIB snapshot after provisioning
- vlan_operation_data: Decoded ME 171 VLAN tagging operation tables
- tcont_flows_data: T-CONT → GEM Port → Priority Queue traffic hierarchy
- topology_data: ME relationship graph (ANI/UNI/bridge/IW connections)

CRITICAL INSTRUCTIONS:
1. Strict adherence to ITU-T G.988 specification. Do not hallucinate or guess hex values.
2. If data is missing, incomplete, or ambiguous, explicitly state "Data insufficient for analysis" instead of making assumptions.
3. Pay special attention to ME 171 (VLAN Tagging Operation) Table row entries. Check if the mapping rules conflict or if there are invalid inner/outer VLAN treatments
4. MANDATORY MAPPING DERIVATION: You must explicitly trace and deduce the exact data path mapping from the UNI side termination points (PPTP Ethernet UNI, VEIP, or IP Host Config Data) through the bridging MEs to the WAN side GEM Ports and T-CONTs.

Analyze from TWO perspectives:

## 1. Telecom Engineer Perspective
Focus on service provisioning behavior:
- What OLT vendor/behavior is observed?
- What services are provisioned (HSI, VoIP, IPTV, TR-069 management)?
- Is the T-CONT/GEM allocation reasonable for the services?
- Are VLAN treatments correct (translation, transparent, tag/untag)?
- Any anomalies in check_summary that indicate interop issues or instability?
- What should a field engineer pay attention to?

## 2. ONU Firmware Engineer Perspective
Focus on what the ONU must implement correctly:
- What ME instances must the ONU create/maintain from MIB upload?
- What provisioning SET/CREATE operations must the ONU handle?
- Are there any failed or missing ME responses that indicate ONU implementation gaps?
- Is the T-CONT/GEM/PQ mapping correctly reflected in the ONU data path?
- Any vendor-specific MEs the ONU must support?

Be concise and specific. Cite ME class IDs and instance numbers where relevant.
If data is missing or ambiguous, state so clearly rather than guessing.
"""


def build_user_prompt(overview_data: dict) -> str:
    overview_json = json.dumps(overview_data, indent=2)
    return f"""Please analyze the following OMCI capture overview data:

```json
{overview_json}
```

Provide your analysis from both the Telecom Engineer and ONU Firmware Engineer perspectives."""


def call_openrouter(overview_data: dict, api_key: str, model: str) -> str:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/daneshih1125/omcipcap",
        "X-Title": "omcipcap ai-overview",
    }

    payload = {
        "model": model,
        "stream": True,
        "temperature": 0.0,
        "seed": 42,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(overview_data)},
        ],
        "max_tokens": 2048,
    }

    try:
        response = requests.post(
            OPENROUTER_API_URL, headers=headers, json=payload, timeout=120, stream=True
        )
        response.raise_for_status()
        full_text = []
        for line in response.iter_lines():
            if not line:
                continue
            line = line.decode("utf-8")
            if line.startswith("data: "):
                data_str = line[6:]
                if data_str.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                    delta = chunk["choices"][0]["delta"].get("content", "")
                    if delta:
                        print(delta, end="", flush=True)
                        full_text.append(delta)
                except (KeyError, IndexError, json.JSONDecodeError):
                    continue

        print()  # final newline
        return "".join(full_text)
        # data = response.json()
        # return data["choices"][0]["message"]["content"]
    except requests.exceptions.Timeout:
        print("[!] Request timed out. The model may be slow, try again.")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"[!] HTTP error: {e}")
        print(f"    Response: {response.text}")
        sys.exit(1)
    except (KeyError, IndexError) as e:
        print(f"[!] Unexpected response format: {e}")
        print(f"    Response: {response.text}")
        sys.exit(1)


def run_ai_overview(pcap_path: str, model: str = DEFAULT_MODEL):
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print("[!] No API key found.")
        print("    Set OPENROUTER_API_KEY environment variable or use --api-key.")
        sys.exit(1)

    print(f"[*] Generating overview from: {pcap_path}")
    overview_data = generate_pcap_ai_overview_data(pcap_path)

    print(f"[*] Calling AI model: {model}")
    print("[*] Analyzing... (this may take 10-30 seconds)\n")
    print("-" * 60)
    call_openrouter(overview_data, api_key, model)
    print("-" * 60)
