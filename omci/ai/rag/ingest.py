#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import re
import tempfile
from pathlib import Path

from omci import omcimd, omciparser, omcisemantic
from omci.ai.rag.database import (
    COLLECTION_NAME,
    RAGDatabaseError,
    validate_collection_metadata,
)
from omci.ai.rag.semantic_units import SEMANTIC_UNIT_DEFINITIONS
from omci.ai.rag.workspace import (
    PROFILE_CONFIGS,
    WorkspaceInitError,
    _load_ai_dependencies as _load_workspace_ai_dependencies,
    load_embedding_model,
    resolve_workspace,
)
from omci.omci import load_omci_packets


REQUIRED_SECTIONS = (
    "Problem",
    "Root-Cause",
    "Trigger-Condition",
    "How-To-Identify",
    "Solution",
)
SEMANTIC_UNITS = tuple(
    definition.semantic_unit for definition in SEMANTIC_UNIT_DEFINITIONS
)
CANONICAL_SECTIONS = (*REQUIRED_SECTIONS, "Environment")
SUPPORTED_CAPTURE_SUFFIXES = (".pcap", ".pcapng")


class RAGIngestError(Exception):
    """Raised when a RAG issue case cannot be ingested."""


def extract_markdown_section(markdown: str, section_name: str) -> str:
    pattern = re.compile(
        rf"^##\s+{re.escape(section_name)}\s*$"
        rf"(.*?)"
        rf"(?=^##?\s+|\Z)",
        re.MULTILINE | re.DOTALL | re.IGNORECASE,
    )
    match = pattern.search(markdown)
    if match is None:
        raise RAGIngestError(f"Missing required section: {section_name}")
    content = match.group(1).strip()
    if not content:
        raise RAGIngestError(f"Section is empty: {section_name}")
    return " ".join(content.split())


def validate_issue_markdown(text: str) -> None:
    canonical_headings = {
        heading.lower(): heading for heading in CANONICAL_SECTIONS
    }
    section_counts: dict[str, int] = {}
    wrong_level: list[str] = []

    for line in text.splitlines():
        match = re.match(r"^(#{1,6})[ \t]+(.+?)[ \t]*$", line)
        if match:
            level = len(match.group(1))
            heading = match.group(2)
            canonical = canonical_headings.get(heading.lower())
            if canonical is not None and level != 2:
                wrong_level.append(canonical)
            if canonical is not None and level == 2:
                section_counts[canonical] = section_counts.get(canonical, 0) + 1

    if wrong_level:
        raise RAGIngestError(
            "Issue Markdown section(s) must use level-2 headings: "
            + ", ".join(sorted(set(wrong_level)))
        )

    missing = [
        heading for heading in REQUIRED_SECTIONS if heading not in section_counts
    ]
    if missing:
        raise RAGIngestError(
            "Issue Markdown is missing required level-2 section(s): "
            + ", ".join(missing)
        )

    duplicates = [
        heading for heading in REQUIRED_SECTIONS if section_counts.get(heading, 0) > 1
    ]
    if duplicates:
        raise RAGIngestError(
            "Issue Markdown has duplicate required section(s): " + ", ".join(duplicates)
        )

    for heading in REQUIRED_SECTIONS:
        try:
            extract_markdown_section(text, heading)
        except RAGIngestError as exc:
            if "Section is empty" in str(exc):
                raise RAGIngestError(
                    f"Issue Markdown has empty required section(s): {heading}"
                ) from exc
            raise


def make_chunk_id(case_id: str, semantic_unit: str, chunk_index: int) -> str:
    return f"{case_id}:{semantic_unit}:{chunk_index}"


def _encode_tokens(text: str, tokenizer: object) -> list[int]:
    # Suppress Hugging Face "sequence length > model_max_length" warnings.
    # The full token sequence is intentionally encoded here only for custom
    # chunking and is never passed directly to the embedding model.
    token_ids = tokenizer.encode(
        text,
        add_special_tokens=False,
        verbose=False,
    )
    return [int(token_id) for token_id in token_ids]


def _decode_tokens(token_ids: list[int], tokenizer: object) -> str:
    return str(
        tokenizer.decode(
            token_ids,
            skip_special_tokens=True,
            clean_up_tokenization_spaces=False,
        )
    )


def _token_boundary_positions(text: str, tokenizer: object) -> list[list[int]]:
    boundary_patterns = (
        r"(?m)(?=^#{1,6}[ \t]+)",
        r"\n[ \t]*\n+",
        r"(?m)(?=^[ \t]*(?:[-*+]|\d+[.)])[ \t]+)",
        r"\n",
    )
    boundary_positions: list[list[int]] = []
    for pattern in boundary_patterns:
        positions: list[int] = []
        for match in re.finditer(pattern, text):
            character_index = (
                match.start() if pattern.startswith("(?m)(?=") else match.end()
            )
            if character_index <= 0 or character_index >= len(text):
                continue
            token_index = len(_encode_tokens(text[:character_index], tokenizer))
            if token_index > 0 and token_index not in positions:
                positions.append(token_index)
        boundary_positions.append(positions)
    return boundary_positions


def split_semantic_unit(
    text: str,
    tokenizer: object,
    max_tokens: int,
    overlap_tokens: int,
) -> list[str]:
    if max_tokens <= 0:
        raise ValueError("max_tokens must be greater than zero")
    if overlap_tokens < 0 or overlap_tokens >= max_tokens:
        raise ValueError("overlap_tokens must be between zero and max_tokens")
    if not text.strip():
        return []

    token_ids = _encode_tokens(text, tokenizer)
    if len(token_ids) <= max_tokens:
        return [text]

    boundary_positions = _token_boundary_positions(text, tokenizer)
    chunks: list[str] = []
    start = 0
    while start < len(token_ids):
        target = min(start + max_tokens, len(token_ids))
        end = target
        if target < len(token_ids):
            minimum_end = start + overlap_tokens + 1
            for positions in boundary_positions:
                candidates = [
                    position
                    for position in positions
                    if minimum_end <= position <= target
                ]
                if candidates:
                    end = max(candidates)
                    break

        chunk = _decode_tokens(token_ids[start:end], tokenizer)
        if chunk.strip():
            chunks.append(chunk)
        if end >= len(token_ids):
            break
        next_start = end - overlap_tokens
        start = next_start if next_start > start else end

    return chunks


def build_chunk_records(
    case_id: str,
    semantic_units: dict[str, str],
    tokenizer: object,
    max_tokens: int,
    overlap_tokens: int,
    issue_file: str,
    pcap_file: str,
    problem: str,
) -> tuple[list[str], list[str], list[dict[str, object]]]:
    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict[str, object]] = []

    for definition in SEMANTIC_UNIT_DEFINITIONS:
        semantic_unit = definition.semantic_unit
        chunks = split_semantic_unit(
            semantic_units.get(semantic_unit, ""),
            tokenizer,
            max_tokens,
            overlap_tokens,
        )
        for chunk_index, document in enumerate(chunks):
            ids.append(make_chunk_id(case_id, semantic_unit, chunk_index))
            documents.append(document)
            metadatas.append(
                {
                    "case_id": case_id,
                    "semantic_unit": semantic_unit,
                    "chunk_index": chunk_index,
                    "priority": definition.priority,
                    "issue_file": issue_file,
                    "pcap_file": pcap_file,
                    "problem": problem,
                }
            )
    return ids, documents, metadatas


def _load_ai_dependencies() -> tuple[object, object]:
    try:
        return _load_workspace_ai_dependencies()
    except WorkspaceInitError as exc:
        raise RAGIngestError(str(exc)) from exc


def _load_workspace_analysis_resources(workspace: Path) -> None:
    from omci.cli import load_mib_json

    mib_json_dir = workspace / "mib-json"
    mib_json_files = sorted(
        (
            path
            for path in mib_json_dir.iterdir()
            if path.is_file() and path.suffix == ".json"
        ),
        key=lambda path: path.name,
    )
    for mib_json_path in mib_json_files:
        if not load_mib_json(str(mib_json_path)):
            raise RAGIngestError(
                f"Failed to load workspace MIB JSON: '{mib_json_path}'"
            )

    semantics_dir = workspace / "semantics"
    try:
        loaded = omcisemantic.load_external_semantics(str(semantics_dir))
    except Exception as exc:
        raise RAGIngestError(
            f"Failed to load semantic plugins from '{semantics_dir}': {exc}"
        ) from exc
    if not loaded:
        raise RAGIngestError(f"Failed to load semantic plugins from '{semantics_dir}'")


def compose_service_path(*sections: str) -> str:
    return "\n\n".join(
        section.strip()
        for section in sections
        if section and section.strip()
    )


def _analyze_pcap(pcap_path: Path, issue_text: str) -> dict[str, str]:
    packets = load_omci_packets(str(pcap_path), include_raw=True)
    check_data = omciparser.get_check_results(packets, only_failed=True)
    upload_data = omciparser.get_mib_db_data(packets, only_upload=True)
    full_data = omciparser.get_mib_db_data(packets)
    vendor_data = omciparser.get_mib_db_data(packets, only_vendor=True)
    full_mib = omciparser.get_all_mib_db(packets)
    vlan_data = omciparser.get_vlan_data(full_mib)
    flow_data = omciparser.get_flow_data(full_mib)
    topology_data = omciparser.get_topology_data(packets)
    service_path = compose_service_path(
        omcimd.render_vlan_md(vlan_data),
        omcimd.render_tcont_flow_md(flow_data),
        omcimd.render_topology_md(topology_data),
    )

    return {
        "issue_summary": issue_text,
        "failed_check_results": omcimd.render_check_md(check_data),
        "core_mib_summary": omcimd.render_mibdb_md(full_data, short=True),
        "service_path": service_path,
        "upload_mib": omcimd.render_mibdb_md(upload_data, short=True),
        "vendor_specific_mib": omcimd.render_mibdb_md(vendor_data, short=True),
        "full_mib": omcimd.render_mibdb_md(full_data, short=True),
    }


def _collection_for_workspace(
    chromadb_module: object, workspace: Path, config: dict[str, object]
) -> object:
    try:
        client = chromadb_module.PersistentClient(path=str(workspace / "db"))
        metadata = {
            "hnsw:space": "cosine",
            "db_schema_version": config["db_schema_version"],
            "profile_id": config["profile_id"],
            "omcipcap_version": config["omcipcap_version"],
        }
        collection = client.get_or_create_collection(
            name=COLLECTION_NAME, metadata=metadata
        )
    except Exception as exc:
        raise RAGIngestError(
            f"Cannot open ChromaDB in '{workspace / 'db'}': {exc}"
        ) from exc

    try:
        validate_collection_metadata(collection.metadata, config)
    except RAGDatabaseError as exc:
        raise RAGIngestError(
            str(exc)
        ) from exc
    return collection


def _existing_case(collection: object, case_id: str) -> dict[str, object]:
    return collection.get(
        where={"case_id": case_id},
        include=["documents", "metadatas", "embeddings"],
    )


def _restore_case(collection: object, previous: dict[str, object]) -> None:
    ids = previous.get("ids") or []
    if not ids:
        return
    collection.upsert(
        ids=ids,
        documents=previous.get("documents"),
        metadatas=previous.get("metadatas"),
        embeddings=previous.get("embeddings"),
    )


def _stage_issue_markdown(stored_issue: Path, issue_text: str) -> Path:
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=stored_issue.parent,
            prefix=f".{stored_issue.name}.",
            delete=False,
        ) as f:
            f.write(issue_text)
            return Path(f.name)
    except OSError as exc:
        raise RAGIngestError(
            f"Cannot stage issue Markdown '{stored_issue}': {exc}"
        ) from exc


def _restore_issue_markdown(stored_issue: Path, previous_issue: bytes | None) -> None:
    if previous_issue is None:
        if stored_issue.exists():
            stored_issue.unlink()
        return

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=stored_issue.parent,
            prefix=f".{stored_issue.name}.restore.",
            delete=False,
        ) as f:
            temp_path = Path(f.name)
            f.write(previous_issue)
        temp_path.replace(stored_issue)
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def ingest_case(
    case_id: str,
    issue_path: Path,
    pcap_path: Path,
) -> bool:
    try:
        workspace, config = resolve_workspace()
    except WorkspaceInitError as exc:
        raise RAGIngestError(str(exc)) from exc

    if (
        not case_id.strip()
        or case_id in {".", ".."}
        or "/" in case_id
        or "\\" in case_id
        or Path(case_id).name != case_id
    ):
        raise RAGIngestError("Case ID must be a non-empty filename-safe value")
    if not issue_path.is_file():
        raise RAGIngestError(f"Issue Markdown file not found: '{issue_path}'")
    if not pcap_path.is_file():
        raise RAGIngestError(f"PCAP file not found: '{pcap_path}'")
    if pcap_path.suffix.lower() not in SUPPORTED_CAPTURE_SUFFIXES:
        supported = ", ".join(SUPPORTED_CAPTURE_SUFFIXES)
        raise RAGIngestError(
            f"Unsupported capture format '{pcap_path.suffix}'. Supported: {supported}"
        )

    try:
        issue_text = issue_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RAGIngestError(
            f"Cannot read issue Markdown '{issue_path}': {exc}"
        ) from exc
    validate_issue_markdown(issue_text)
    problem = extract_markdown_section(issue_text, "Problem")

    _load_workspace_analysis_resources(workspace)
    chromadb_module, _ = _load_ai_dependencies()
    collection = _collection_for_workspace(chromadb_module, workspace, config)
    try:
        previous = _existing_case(collection, case_id)
    except Exception as exc:
        raise RAGIngestError(
            f"Cannot inspect existing RAG case '{case_id}': {exc}"
        ) from exc
    previous_ids = previous.get("ids") or []
    stored_issue = workspace / "issues" / f"{case_id}.md"

    if previous_ids or stored_issue.exists():
        print(f'Case "{case_id}" already exists.\n')
        answer = input("Replace existing case? [y/N] ")
        if answer.lower() != "y":
            print("Ingestion cancelled.")
            return False

    semantic_units = _analyze_pcap(pcap_path, issue_text)
    profile = str(config["profile_id"])
    profile_config = PROFILE_CONFIGS[profile]
    try:
        model = load_embedding_model(profile, local_files_only=True)
    except WorkspaceInitError as exc:
        raise RAGIngestError(
            f"Embedding model for profile '{profile}' is not available locally.\n\n"
            "Run:\n\n"
            f"    omcipcap ai rag init --profile {profile} --dir {workspace}"
        ) from exc
    try:
        ids, documents, metadatas = build_chunk_records(
            case_id,
            semantic_units,
            model.tokenizer,
            int(profile_config["max_tokens"]),
            int(profile_config["token_overlap"]),
            stored_issue.name,
            pcap_path.name,
            problem,
        )
        vectors = model.encode(documents)
        embeddings = [[float(value) for value in vector] for vector in vectors]
    except Exception as exc:
        raise RAGIngestError(f"Failed to generate embeddings: {exc}") from exc

    previous_issue = stored_issue.read_bytes() if stored_issue.exists() else None
    temp_issue = _stage_issue_markdown(stored_issue, issue_text)

    # ChromaDB has no cross-resource transaction with the issue file. Keep complete
    # backups and restore both resources if any destructive replacement step fails.
    try:
        collection.delete(where={"case_id": case_id})
        temp_issue.replace(stored_issue)
        collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
            embeddings=embeddings,
        )
    except Exception as exc:
        try:
            collection.delete(where={"case_id": case_id})
            _restore_case(collection, previous)
            _restore_issue_markdown(stored_issue, previous_issue)
        except Exception as restore_exc:
            raise RAGIngestError(
                f"Failed to store RAG case '{case_id}' and restore its previous data: "
                f"{restore_exc}"
            ) from restore_exc
        raise RAGIngestError(f"Failed to store RAG case '{case_id}': {exc}") from exc
    finally:
        try:
            temp_issue.unlink()
        except FileNotFoundError:
            pass

    return True
