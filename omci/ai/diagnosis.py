#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import os
from pathlib import Path
import sys
from typing import TextIO

from omci import omcimd, omciparser, overview
from omci.ai.providers import create_provider
from omci.omci import load_omci_packets


DEFAULT_SYSTEM_PROMPT = """You are a senior Broadband Access Network engineer.

You are an expert in:

- GPON
- XGS-PON
- OMCI
- ITU-T G.988
- legacy GPON specifications including the ITU-T G.984 series
- ONU provisioning
- OLT provisioning
- OMCI interoperability
- ONU Managed Entities
- VLAN provisioning
- T-CONT
- GEM Port
- Priority Queue
- ONU topology
- vendor-specific OMCI implementation differences

In the next section you will receive:

1. A user-reported problem.

2. OMCIPcap-generated analysis.

The supplied OMCIPcap analysis typically contains information including:

- protocol validation (check)
- semantic MIB database
- ONU capability
- VLAN analysis
- traffic hierarchy (T-CONT → GEM → Priority Queue)
- ONU logical topology

Use the supplied OMCIPcap analysis as the primary source of evidence.

If the user-reported problem conflicts with the supplied OMCIPcap analysis,
identify and explain the discrepancy instead of assuming either is correct.

OMCIPcap reconstructs semantic information from observed OMCI traffic.

The inferred MIB represents the observed provisioning behavior.

It is not guaranteed to be the ONU runtime state.

Always consider:

- missing packets
- incomplete captures
- failed OMCI operations
- retransmissions
- unsupported Managed Entities
- partial provisioning
- interrupted captures

Do not assume an ONU state change unless supported by the observed OMCI responses.

When relevant to the user's question:

- answer the user's question directly
- identify the most relevant OMCIPcap evidence
- explain confirmed issues or significant anomalies
- distinguish confirmed findings from assumptions
- provide likely root causes and verification steps only when needed

Do not force a full diagnostic report when the user's question can be answered
directly from the supplied evidence.

When OLT vendor names, ONU vendor names, chipset vendors, software versions,
or product models are mentioned:

- consider known OMCI interoperability characteristics
- relate them to the supplied evidence
- distinguish known behavior from assumptions
- never present assumptions as confirmed facts

Vendor-specific knowledge is supplementary and MUST NOT override the supplied
OMCIPcap evidence.

Do NOT claim to have searched:

- the Internet
- vendor documentation
- internal knowledge bases
- proprietary documents

unless those resources are explicitly provided.

Do NOT invent:

- OMCI packets
- Managed Entities
- Managed Entity attributes
- vendor-specific behavior
- service configuration
- ONU runtime state

Focus on answering the user's questions using the supplied OMCIPcap analysis.
Prioritize correctness, evidence, and technical accuracy over formatting.

Unless the user explicitly requests a specific output format, answer naturally
and concisely."""


class AIDiagnosisError(Exception):
    """Raised when diagnosis inputs or streaming cannot be processed."""


def _read_markdown(path: Path, description: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise AIDiagnosisError(f"{description} file not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise AIDiagnosisError(
            f"{description} file is not valid UTF-8: {path}"
        ) from exc
    except OSError as exc:
        raise AIDiagnosisError(f"Could not read {description} file: {path}") from exc


def load_system_prompt() -> str:
    """Load the configured diagnosis system prompt or return the built-in prompt."""
    configured_path = os.environ.get("AI_DIAG_SYSTEM_PROMPT")
    if configured_path is None:
        return DEFAULT_SYSTEM_PROMPT

    prompt_path = Path(configured_path)
    prompt = _read_markdown(prompt_path, "System prompt")
    if not prompt.strip():
        raise AIDiagnosisError(f"System prompt file is empty: {prompt_path}")
    return prompt


def load_problem_prompt(path: Path) -> str:
    """Load a non-empty user-authored diagnosis problem."""
    prompt = _read_markdown(path, "Problem Markdown")
    if not prompt.strip():
        raise AIDiagnosisError(f"Problem Markdown file is empty: {path}")
    return prompt


def generate_overview_markdown(pcap_path: Path) -> str:
    """Generate the standard OMCIPcap overview Markdown for a capture."""
    overview_data = overview.generate_pcap_ai_overview_data(str(pcap_path))
    return omcimd.render_overview_md(overview_data)


def compose_user_prompt(problem_prompt: str, overview_markdown: str) -> str:
    """Combine the user problem and generated overview into the provider prompt."""
    # Use Setext headings so user-authored Markdown may freely use ATX (`#`)
    # headings without conflicting with the outer prompt sections.
    return (
        "User-Reported Problem\n"
        "=====================\n\n"
        f"{problem_prompt.rstrip()}\n\n"
        "---\n\n"
        "OMCIPcap Analysis\n"
        "=================\n\n"
        f"{overview_markdown.rstrip()}\n"
    )


def generate_full_lifecycle_diff_markdown(
    target_pcap_path: Path,
    golden_pcap_path: Path,
) -> str:
    """Generate a Target-to-Golden semantic diff from full observed MIB state."""
    target_packets = load_omci_packets(str(target_pcap_path), include_raw=False)
    golden_packets = load_omci_packets(str(golden_pcap_path), include_raw=False)
    target_full_mib = omciparser.get_all_mib_db(target_packets)
    golden_full_mib = omciparser.get_all_mib_db(golden_packets)
    diff_data = omciparser.get_mib_diff_data(target_full_mib, golden_full_mib)
    return omcimd.render_diff_md(diff_data)


def compose_diff_user_prompt(
    problem_prompt: str,
    diff_markdown: str,
    golden_overview_markdown: str,
    target_overview_markdown: str,
) -> str:
    """Compose deterministic Target-to-Golden diagnosis context."""
    return (
        "User-Reported Problem\n"
        "=====================\n\n"
        f"{problem_prompt.rstrip()}\n\n"
        "---\n\n"
        "Full Lifecycle Semantic MIB Diff\n"
        "================================\n\n"
        "Comparison direction: Target PCAP → Golden PCAP.\n\n"
        "- `old` values represent the Target PCAP\n"
        "- `new` values represent the Golden PCAP\n"
        "- `added` entries exist only in the Golden PCAP\n"
        "- `removed` entries exist only in the Target PCAP\n"
        "- `modified` entries exist in both captures but differ\n\n"
        f"{diff_markdown.rstrip()}\n\n"
        "---\n\n"
        "OMCIPcap Analysis of the Golden PCAP\n"
        "====================================\n\n"
        f"{golden_overview_markdown.rstrip()}\n\n"
        "---\n\n"
        "OMCIPcap Analysis of the Target PCAP\n"
        "====================================\n\n"
        f"{target_overview_markdown.rstrip()}\n"
    )


def _stream_diagnosis(
    provider_name: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    output: TextIO | None,
) -> None:
    provider = create_provider(provider_name)
    stream = output if output is not None else sys.stdout

    try:
        for fragment in provider.stream_generate(
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        ):
            stream.write(fragment)
            stream.flush()
        stream.write("\n")
        stream.flush()
    except KeyboardInterrupt as exc:
        raise AIDiagnosisError("AI diagnosis streaming interrupted.") from exc


def run_diagnosis(
    pcap_path: Path,
    problem_path: Path,
    provider_name: str,
    model: str,
    output: TextIO | None = None,
) -> None:
    """Generate and stream one AI-assisted PCAP diagnosis."""
    if not pcap_path.is_file():
        raise AIDiagnosisError(f"PCAP file not found: {pcap_path}")

    system_prompt = load_system_prompt()
    problem_prompt = load_problem_prompt(problem_path)
    overview_markdown = generate_overview_markdown(pcap_path)
    user_prompt = compose_user_prompt(problem_prompt, overview_markdown)
    _stream_diagnosis(provider_name, model, system_prompt, user_prompt, output)


def run_diagnosis_diff(
    target_pcap_path: Path,
    golden_pcap_path: Path,
    problem_path: Path,
    provider_name: str,
    model: str,
    output: TextIO | None = None,
) -> None:
    """Generate and stream a Target-to-Golden AI-assisted diagnosis."""
    if not target_pcap_path.is_file():
        raise AIDiagnosisError(f"Target PCAP file not found: {target_pcap_path}")
    if not golden_pcap_path.is_file():
        raise AIDiagnosisError(f"Golden PCAP file not found: {golden_pcap_path}")

    system_prompt = load_system_prompt()
    problem_prompt = load_problem_prompt(problem_path)
    diff_markdown = generate_full_lifecycle_diff_markdown(
        target_pcap_path,
        golden_pcap_path,
    )
    golden_overview_markdown = generate_overview_markdown(golden_pcap_path)
    target_overview_markdown = generate_overview_markdown(target_pcap_path)
    user_prompt = compose_diff_user_prompt(
        problem_prompt,
        diff_markdown,
        golden_overview_markdown,
        target_overview_markdown,
    )
    _stream_diagnosis(provider_name, model, system_prompt, user_prompt, output)
