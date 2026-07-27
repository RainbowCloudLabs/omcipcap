#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import builtins
from pathlib import Path

import pytest

from omci.ai.rag import ingest as rag_ingest
from omci.ai.rag.ingest import (
    RAGIngestError,
    SEMANTIC_UNITS,
    build_chunk_records,
    extract_markdown_section,
    ingest_case,
    make_chunk_id,
    split_semantic_unit,
    validate_issue_markdown,
)
from omci.ai.rag.semantic_units import SEMANTIC_UNIT_DEFINITIONS
from omci.ai.rag import workspace as rag_workspace
from omci.ai.rag.workspace import (
    PROFILE_CONFIGS,
    WorkspaceInitError,
    initialize_workspace,
)


def issue_markdown(include_environment: bool = True) -> str:
    environment = "## Environment\nONU Vendor: Example\n\n" if include_environment else ""
    return (
        "## Problem\nService is unavailable.\n\n"
        f"{environment}"
        "## Root-Cause\nIncorrect VLAN rule.\n\n"
        "## Trigger-Condition\nONU reboot.\n\n"
        "## How-To-Identify\nCheck the VLAN operation table.\n\n"
        "## Solution\nCorrect the VLAN rule.\n\n"
        "## Notes\nPreserve this additional section.\n"
    )


@pytest.fixture(autouse=True)
def avoid_model_download(monkeypatch: pytest.MonkeyPatch) -> None:
    def prepare_model(profile: str) -> object:
        return {"profile": profile}

    monkeypatch.setattr(rag_workspace, "prepare_embedding_model", prepare_model)


def semantic_units(issue_text: str) -> dict[str, str]:
    return {unit: f"{unit}\n{issue_text}" for unit in SEMANTIC_UNITS}


class FakeCollection:
    def __init__(self) -> None:
        self.metadata: dict[str, object] = {}
        self.records: dict[str, dict[str, object]] = {}
        self.fail_next_upsert = False

    def get(
        self,
        where: dict[str, object],
        include: list[str],
    ) -> dict[str, object]:
        del include
        case_id = where["case_id"]
        selected = [
            (chunk_id, record)
            for chunk_id, record in self.records.items()
            if record["metadata"]["case_id"] == case_id
        ]
        return {
            "ids": [chunk_id for chunk_id, _ in selected],
            "documents": [record["document"] for _, record in selected],
            "metadatas": [record["metadata"] for _, record in selected],
            "embeddings": [record["embedding"] for _, record in selected],
        }

    def upsert(
        self,
        ids: list[str],
        documents: list[str],
        metadatas: list[dict[str, object]],
        embeddings: list[list[float]],
    ) -> None:
        if self.fail_next_upsert:
            self.fail_next_upsert = False
            raise RuntimeError("injected upsert failure")
        for chunk_id, document, metadata, embedding in zip(
            ids, documents, metadatas, embeddings
        ):
            self.records[chunk_id] = {
                "document": document,
                "metadata": metadata,
                "embedding": embedding,
            }

    def delete(
        self,
        ids: list[str] | None = None,
        where: dict[str, object] | None = None,
    ) -> None:
        if ids is not None:
            for chunk_id in ids:
                self.records.pop(chunk_id, None)
        if where is not None:
            case_id = where["case_id"]
            for chunk_id in list(self.records):
                if self.records[chunk_id]["metadata"]["case_id"] == case_id:
                    del self.records[chunk_id]


class FakeClient:
    def __init__(self, collection: FakeCollection) -> None:
        self.collection = collection

    def get_or_create_collection(
        self, name: str, metadata: dict[str, object]
    ) -> FakeCollection:
        del name
        if not self.collection.metadata:
            self.collection.metadata = metadata
        return self.collection


class FakeChroma:
    def __init__(self, collection: FakeCollection) -> None:
        self.collection = collection
        self.paths: list[Path] = []

    def PersistentClient(self, path: str) -> FakeClient:
        self.paths.append(Path(path))
        return FakeClient(self.collection)


class FakeModel:
    def __init__(self) -> None:
        self.tokenizer = SingleTokenTokenizer()

    def encode(self, documents: list[str]) -> list[list[float]]:
        return [[float(index), float(len(document))] for index, document in enumerate(documents)]


class FakeSentenceTransformer:
    def __init__(self, model_name: str) -> None:
        self.model_name = model_name
        self.tokenizer = SingleTokenTokenizer()

    def encode(self, documents: list[str]) -> list[list[float]]:
        return FakeModel().encode(documents)


class SingleTokenTokenizer:
    def encode(
        self,
        text: str,
        add_special_tokens: bool = False,
        **kwargs: object,
    ) -> list[int]:
        del add_special_tokens, kwargs
        return [] if not text else [1]

    def decode(
        self,
        token_ids: list[int],
        skip_special_tokens: bool = True,
        clean_up_tokenization_spaces: bool = False,
    ) -> str:
        del token_ids, skip_special_tokens, clean_up_tokenization_spaces
        return "token"


class CharacterTokenizer:
    def encode(
        self,
        text: str,
        add_special_tokens: bool = False,
        **kwargs: object,
    ) -> list[int]:
        del add_special_tokens, kwargs
        return [ord(character) for character in text]

    def decode(
        self,
        token_ids: list[int],
        skip_special_tokens: bool = True,
        clean_up_tokenization_spaces: bool = False,
    ) -> str:
        del skip_special_tokens, clean_up_tokenization_spaces
        return "".join(chr(token_id) for token_id in token_ids)


def prepare_ingest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path, FakeCollection, FakeChroma]:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    workspace = tmp_path / "workspace"
    initialize_workspace(workspace, "standard")
    issue_path = tmp_path / "issue.md"
    issue_path.write_text(issue_markdown(), encoding="utf-8")
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")
    collection = FakeCollection()
    chroma = FakeChroma(collection)

    def load_dependencies() -> tuple[object, object]:
        return chroma, FakeSentenceTransformer

    def load_model(profile: str, local_files_only: bool) -> FakeModel:
        assert profile == "standard"
        assert local_files_only
        return FakeModel()

    def analyze(path: Path, issue_text: str) -> dict[str, str]:
        assert path == pcap_path
        return semantic_units(issue_text)

    def load_resources(path: Path) -> None:
        assert path == workspace

    monkeypatch.setattr(rag_ingest, "_load_ai_dependencies", load_dependencies)
    monkeypatch.setattr(rag_ingest, "load_embedding_model", load_model)
    monkeypatch.setattr(rag_ingest, "_analyze_pcap", analyze)
    monkeypatch.setattr(
        rag_ingest, "_load_workspace_analysis_resources", load_resources
    )
    return workspace, issue_path, pcap_path, collection, chroma


def test_successful_ingestion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, issue_path, pcap_path, collection, chroma = prepare_ingest(
        tmp_path, monkeypatch
    )

    assert ingest_case("CASE-001", issue_path, pcap_path)

    assert (
        workspace / "issues" / "CASE-001.md"
    ).read_text(encoding="utf-8") == issue_markdown()
    assert chroma.paths == [workspace / "db"]
    assert collection.metadata["hnsw:space"] == "cosine"
    assert list(collection.records) == [
        make_chunk_id("CASE-001", unit, 0) for unit in SEMANTIC_UNITS
    ]
    for unit, record in zip(SEMANTIC_UNITS, collection.records.values()):
        priority = next(
            definition.priority
            for definition in SEMANTIC_UNIT_DEFINITIONS
            if definition.semantic_unit == unit
        )
        assert record["metadata"] == {
            "case_id": "CASE-001",
            "semantic_unit": unit,
            "chunk_index": 0,
            "priority": priority,
            "issue_file": "CASE-001.md",
            "pcap_file": "sample.pcap",
            "problem": "Service is unavailable.",
        }


def test_ingest_loads_shared_profile_model_from_local_cache_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, issue_path, pcap_path, _, _ = prepare_ingest(tmp_path, monkeypatch)
    model_loads: list[tuple[str, bool, str]] = []

    def load_model(profile: str, local_files_only: bool) -> FakeModel:
        model_loads.append(
            (
                profile,
                local_files_only,
                str(PROFILE_CONFIGS[profile]["model"]),
            )
        )
        return FakeModel()

    monkeypatch.setattr(rag_ingest, "load_embedding_model", load_model)

    assert ingest_case("CASE-001", issue_path, pcap_path)

    assert model_loads == [
        (
            "standard",
            True,
            "sentence-transformers/all-MiniLM-L6-v2",
        )
    ]
    assert (workspace / "issues" / "CASE-001.md").is_file()


def test_ingest_local_model_failure_preserves_existing_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, issue_path, pcap_path, collection, _ = prepare_ingest(
        tmp_path, monkeypatch
    )
    old_id = make_chunk_id("CASE-001", "issue_summary", 0)
    old_metadata = {
        "case_id": "CASE-001",
        "semantic_unit": "issue_summary",
        "chunk_index": 0,
        "issue_file": "CASE-001.md",
        "pcap_file": "old.pcap",
    }
    collection.records[old_id] = {
        "document": "old document",
        "metadata": old_metadata,
        "embedding": [1.0],
    }
    stored_issue = workspace / "issues" / "CASE-001.md"
    stored_issue.write_text("old issue", encoding="utf-8")

    def confirm_replace(prompt: str) -> str:
        assert prompt == "Replace existing case? [y/N] "
        return "y"

    def fail_local_load(profile: str, local_files_only: bool) -> object:
        assert profile == "standard"
        assert local_files_only
        raise WorkspaceInitError("model is absent from the local cache")

    monkeypatch.setattr("builtins.input", confirm_replace)
    monkeypatch.setattr(rag_ingest, "load_embedding_model", fail_local_load)

    with pytest.raises(
        RAGIngestError,
        match=(
            r"(?s)not available locally.*"
            r"rag init --profile standard --dir .*workspace"
        ),
    ):
        ingest_case("CASE-001", issue_path, pcap_path)

    assert stored_issue.read_text(encoding="utf-8") == "old issue"
    assert collection.records == {
        old_id: {
            "document": "old document",
            "metadata": old_metadata,
            "embedding": [1.0],
        }
    }


def test_workspace_analysis_resources_use_existing_loaders_in_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    workspace = initialize_workspace(tmp_path / "workspace", "standard")
    mib_dir = workspace / "mib-json"
    (mib_dir / "b.json").write_text("{}", encoding="utf-8")
    (mib_dir / "a.json").write_text("{}", encoding="utf-8")
    (mib_dir / "ignored.JSON").write_text("{}", encoding="utf-8")
    (mib_dir / "ignored.txt").write_text("{}", encoding="utf-8")
    nested = mib_dir / "nested"
    nested.mkdir()
    (nested / "ignored.json").write_text("{}", encoding="utf-8")
    loaded_resources: list[str] = []

    def load_mib_json(path: str) -> bool:
        loaded_resources.append(Path(path).name)
        return True

    def load_semantics(path: str) -> bool:
        loaded_resources.append(str(Path(path).relative_to(workspace)))
        return True

    monkeypatch.setattr("omci.cli.load_mib_json", load_mib_json)
    monkeypatch.setattr(
        rag_ingest.omcisemantic, "load_external_semantics", load_semantics
    )

    rag_ingest._load_workspace_analysis_resources(workspace)

    assert loaded_resources == ["a.json", "b.json", "semantics"]


def test_workspace_resources_load_before_semantic_unit_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, issue_path, pcap_path, _, _ = prepare_ingest(tmp_path, monkeypatch)
    events: list[str] = []

    def load_resources(workspace: Path) -> None:
        del workspace
        events.append("resources")

    def analyze(path: Path, issue_text: str) -> dict[str, str]:
        del path
        events.append("analysis")
        return semantic_units(issue_text)

    monkeypatch.setattr(
        rag_ingest, "_load_workspace_analysis_resources", load_resources
    )
    monkeypatch.setattr(rag_ingest, "_analyze_pcap", analyze)

    assert ingest_case("CASE-001", issue_path, pcap_path)
    assert events == ["resources", "analysis"]


def test_invalid_workspace_mib_json_preserves_existing_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual_resource_loader = rag_ingest._load_workspace_analysis_resources
    workspace, issue_path, pcap_path, collection, _ = prepare_ingest(
        tmp_path, monkeypatch
    )
    invalid_json = workspace / "mib-json" / "invalid.json"
    invalid_json.write_text("{invalid", encoding="utf-8")
    stored_issue = workspace / "issues" / "CASE-001.md"
    stored_issue.write_text("old issue", encoding="utf-8")
    old_id = make_chunk_id("CASE-001", "issue_summary", 0)
    collection.records[old_id] = {
        "document": "old document",
        "metadata": {
            "case_id": "CASE-001",
            "semantic_unit": "issue_summary",
            "chunk_index": 0,
            "issue_file": "CASE-001.md",
            "pcap_file": "old.pcap",
        },
        "embedding": [1.0],
    }

    def reject_mib_json(path: str) -> bool:
        assert Path(path) == invalid_json
        return False

    def fail_if_analyzed(path: Path, issue_text: str) -> dict[str, str]:
        del path, issue_text
        raise AssertionError("analysis must not start")

    monkeypatch.setattr("omci.cli.load_mib_json", reject_mib_json)
    monkeypatch.setattr(
        rag_ingest, "_load_workspace_analysis_resources", actual_resource_loader
    )
    monkeypatch.setattr(rag_ingest, "_analyze_pcap", fail_if_analyzed)

    with pytest.raises(RAGIngestError, match="invalid.json"):
        ingest_case("CASE-001", issue_path, pcap_path)

    assert stored_issue.read_text(encoding="utf-8") == "old issue"
    assert collection.records[old_id]["document"] == "old document"


def test_semantic_plugin_error_preserves_existing_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual_resource_loader = rag_ingest._load_workspace_analysis_resources
    workspace, issue_path, pcap_path, collection, _ = prepare_ingest(
        tmp_path, monkeypatch
    )
    plugin = workspace / "semantics" / "broken.py"
    plugin.write_text("raise RuntimeError('broken plugin')", encoding="utf-8")
    stored_issue = workspace / "issues" / "CASE-001.md"
    stored_issue.write_text("old issue", encoding="utf-8")
    old_id = make_chunk_id("CASE-001", "issue_summary", 0)
    collection.records[old_id] = {
        "document": "old document",
        "metadata": {
            "case_id": "CASE-001",
            "semantic_unit": "issue_summary",
            "chunk_index": 0,
            "issue_file": "CASE-001.md",
            "pcap_file": "old.pcap",
        },
        "embedding": [1.0],
    }

    def load_mib_json(path: str) -> bool:
        del path
        return True

    def fail_semantics(path: str) -> bool:
        assert Path(path) == workspace / "semantics"
        raise RuntimeError(f"broken plugin: {plugin.name}")

    monkeypatch.setattr("omci.cli.load_mib_json", load_mib_json)
    monkeypatch.setattr(
        rag_ingest.omcisemantic, "load_external_semantics", fail_semantics
    )
    monkeypatch.setattr(
        rag_ingest, "_load_workspace_analysis_resources", actual_resource_loader
    )

    with pytest.raises(RAGIngestError, match="broken.py"):
        ingest_case("CASE-001", issue_path, pcap_path)

    assert stored_issue.read_text(encoding="utf-8") == "old issue"
    assert collection.records[old_id]["document"] == "old document"


def test_all_required_sections_present() -> None:
    validate_issue_markdown(issue_markdown())


def test_extract_problem_section_normalizes_multiline_content() -> None:
    markdown = (
        "# CASE-001\n\n"
        "## Problem\n\n"
        "The ONU completes MIB synchronization, but the expected VEIP\n"
        "managed entity is   not created.\n\n"
        "Subscriber service fails.\n\n"
        "## Environment\nVendor: Example\n"
    )

    assert extract_markdown_section(markdown, "Problem") == (
        "The ONU completes MIB synchronization, but the expected VEIP managed "
        "entity is not created. Subscriber service fails."
    )


def test_extract_problem_stops_before_next_level_two_heading() -> None:
    markdown = "## Problem\nFailure text.\n\n## Environment\nVendor: Example\n"

    problem = extract_markdown_section(markdown, "Problem")

    assert problem == "Failure text."
    assert "Environment" not in problem


def test_extract_problem_stops_before_next_level_one_heading() -> None:
    markdown = "## Problem\nFailure text.\n\n# Another Case\nOther text\n"

    assert extract_markdown_section(markdown, "Problem") == "Failure text."


def test_extract_problem_heading_is_case_insensitive() -> None:
    assert (
        extract_markdown_section("## pRoBlEm\nFailure text.\n", "Problem")
        == "Failure text."
    )


def test_extract_problem_rejects_missing_section() -> None:
    with pytest.raises(RAGIngestError, match="Missing required section: Problem"):
        extract_markdown_section("## Environment\nVendor: Example\n", "Problem")


def test_extract_problem_rejects_empty_section() -> None:
    with pytest.raises(RAGIngestError, match="Section is empty: Problem"):
        extract_markdown_section("## Problem\n \n## Environment\nVendor\n", "Problem")


def test_missing_required_section() -> None:
    text = issue_markdown().replace("## Solution", "## Workaround")

    with pytest.raises(RAGIngestError, match="Solution"):
        validate_issue_markdown(text)


def test_empty_required_section() -> None:
    text = issue_markdown().replace(
        "## Root-Cause\nIncorrect VLAN rule.",
        "## Root-Cause\n   ",
    )

    with pytest.raises(RAGIngestError, match="Root-Cause"):
        validate_issue_markdown(text)


def test_wrong_required_heading_level() -> None:
    text = issue_markdown().replace("## Solution", "### Solution")

    with pytest.raises(RAGIngestError, match="level-2.*Solution"):
        validate_issue_markdown(text)


def test_duplicate_required_section() -> None:
    text = issue_markdown() + "\n## Problem\nDuplicate problem.\n"

    with pytest.raises(RAGIngestError, match="duplicate.*Problem"):
        validate_issue_markdown(text)


def test_optional_environment_may_be_omitted() -> None:
    validate_issue_markdown(issue_markdown(include_environment=False))


def test_optional_environment_may_be_present() -> None:
    validate_issue_markdown(issue_markdown(include_environment=True))


def test_environment_must_use_level_two_heading() -> None:
    text = issue_markdown().replace("## Environment", "### Environment")

    with pytest.raises(RAGIngestError, match="level-2.*Environment"):
        validate_issue_markdown(text)


def test_additional_section_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, issue_path, pcap_path, _, _ = prepare_ingest(tmp_path, monkeypatch)

    assert ingest_case("CASE-001", issue_path, pcap_path)

    stored = (workspace / "issues" / "CASE-001.md").read_text(encoding="utf-8")
    assert stored == issue_markdown()
    assert "## Notes\nPreserve this additional section." in stored


@pytest.mark.parametrize("answer", ["n", "N", "", "anything"])
def test_duplicate_case_cancelled(
    answer: str,
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, issue_path, pcap_path, collection, _ = prepare_ingest(
        tmp_path, monkeypatch
    )
    old_id = make_chunk_id("CASE-001", "issue_summary", 0)
    collection.records[old_id] = {
        "document": "old",
        "metadata": {
            "case_id": "CASE-001",
            "semantic_unit": "issue_summary",
            "chunk_index": 0,
            "issue_file": "CASE-001.md",
            "pcap_file": "old.pcap",
        },
        "embedding": [1.0],
    }

    def cancel_replace(prompt: str) -> str:
        assert prompt == "Replace existing case? [y/N] "
        return answer

    monkeypatch.setattr("builtins.input", cancel_replace)

    assert not ingest_case("CASE-001", issue_path, pcap_path)
    assert collection.records[old_id]["document"] == "old"
    assert not (workspace / "issues" / "CASE-001.md").exists()


def test_duplicate_case_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, issue_path, pcap_path, collection, _ = prepare_ingest(
        tmp_path, monkeypatch
    )
    collection.records["old-stale-id"] = {
        "document": "old",
        "metadata": {
            "case_id": "CASE-001",
            "semantic_unit": "issue_summary",
            "chunk_index": 1,
            "issue_file": "CASE-001.md",
            "pcap_file": "old.pcap",
        },
        "embedding": [1.0],
    }
    (workspace / "issues" / "CASE-001.md").write_text("old", encoding="utf-8")

    def confirm_replace(prompt: str) -> str:
        assert prompt == "Replace existing case? [y/N] "
        return "y"

    monkeypatch.setattr("builtins.input", confirm_replace)

    assert ingest_case("CASE-001", issue_path, pcap_path)
    assert "old-stale-id" not in collection.records
    assert len(collection.records) == len(SEMANTIC_UNITS)
    assert (workspace / "issues" / "CASE-001.md").read_text() == issue_markdown()


def test_replacement_updates_problem_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, issue_path, pcap_path, collection, _ = prepare_ingest(
        tmp_path, monkeypatch
    )
    assert ingest_case("CASE-001", issue_path, pcap_path)

    issue_path.write_text(
        issue_markdown().replace(
            "Service is unavailable.",
            "Updated multiline\nproblem description.",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("builtins.input", lambda prompt: "y")

    assert ingest_case("CASE-001", issue_path, pcap_path)
    assert {
        record["metadata"]["problem"]
        for record in collection.records.values()
    } == {"Updated multiline problem description."}


def test_failed_replacement_restores_previous_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, issue_path, pcap_path, collection, _ = prepare_ingest(
        tmp_path, monkeypatch
    )
    old_id = make_chunk_id("CASE-001", "issue_summary", 0)
    old_metadata = {
        "case_id": "CASE-001",
        "semantic_unit": "issue_summary",
        "chunk_index": 0,
        "issue_file": "CASE-001.md",
        "pcap_file": "old.pcap",
    }
    collection.records[old_id] = {
        "document": "old document",
        "metadata": old_metadata,
        "embedding": [1.0],
    }
    stored_issue = workspace / "issues" / "CASE-001.md"
    stored_issue.write_text("old issue", encoding="utf-8")

    def confirm_replace(prompt: str) -> str:
        assert prompt == "Replace existing case? [y/N] "
        return "Y"

    monkeypatch.setattr("builtins.input", confirm_replace)
    collection.fail_next_upsert = True

    with pytest.raises(RAGIngestError, match="Failed to store"):
        ingest_case("CASE-001", issue_path, pcap_path)

    assert collection.records == {
        old_id: {
            "document": "old document",
            "metadata": old_metadata,
            "embedding": [1.0],
        }
    }
    assert stored_issue.read_text(encoding="utf-8") == "old issue"


def test_chunk_ids_are_deterministic() -> None:
    first = [
        make_chunk_id("CASE-001", semantic_unit, 0)
        for semantic_unit in SEMANTIC_UNITS
    ]
    second = [
        make_chunk_id("CASE-001", semantic_unit, 0)
        for semantic_unit in SEMANTIC_UNITS
    ]

    assert first == second
    assert first[0] == "CASE-001:issue_summary:0"


def test_text_below_profile_limit_produces_one_chunk() -> None:
    tokenizer = CharacterTokenizer()

    assert split_semantic_unit("abcde", tokenizer, 6, 2) == ["abcde"]


def test_text_at_profile_limit_produces_one_chunk() -> None:
    tokenizer = CharacterTokenizer()

    assert split_semantic_unit("abcdef", tokenizer, 6, 2) == ["abcdef"]


def test_text_above_profile_limit_produces_multiple_chunks() -> None:
    tokenizer = CharacterTokenizer()

    chunks = split_semantic_unit("abcdefghijk", tokenizer, 6, 2)

    assert len(chunks) > 1


def test_profiles_use_different_chunk_limits() -> None:
    tokenizer = CharacterTokenizer()
    text = "x" * 300
    standard = PROFILE_CONFIGS["standard"]
    workstation = PROFILE_CONFIGS["workstation"]

    standard_chunks = split_semantic_unit(
        text,
        tokenizer,
        int(standard["max_tokens"]),
        int(standard["token_overlap"]),
    )
    workstation_chunks = split_semantic_unit(
        text,
        tokenizer,
        int(workstation["max_tokens"]),
        int(workstation["token_overlap"]),
    )

    assert len(standard_chunks) > 1
    assert len(workstation_chunks) == 1


def test_chunk_overlap_is_applied() -> None:
    tokenizer = CharacterTokenizer()
    chunks = split_semantic_unit("abcdefghijk", tokenizer, 6, 2)

    for previous, current in zip(chunks, chunks[1:]):
        previous_tokens = tokenizer.encode(previous, add_special_tokens=False)
        current_tokens = tokenizer.encode(current, add_special_tokens=False)
        assert previous_tokens[-2:] == current_tokens[:2]


def test_all_chunks_remain_under_token_limit() -> None:
    tokenizer = CharacterTokenizer()
    chunks = split_semantic_unit("abcdefghijklmnopqrstuvwxyz", tokenizer, 7, 2)

    assert all(
        len(tokenizer.encode(chunk, add_special_tokens=False)) <= 7
        for chunk in chunks
    )


def test_chunk_indices_are_sequential_per_semantic_unit() -> None:
    tokenizer = CharacterTokenizer()
    semantic_data = {
        "issue_summary": "abcdefghijk",
        "failed_check_results": "mnopqrstuvw",
    }

    ids, _, metadatas = build_chunk_records(
        "CASE-001",
        semantic_data,
        tokenizer,
        6,
        2,
        "CASE-001.md",
        "sample.pcap",
        "Problem summary",
    )

    issue_indices = [
        metadata["chunk_index"]
        for metadata in metadatas
        if metadata["semantic_unit"] == "issue_summary"
    ]
    check_indices = [
        metadata["chunk_index"]
        for metadata in metadatas
        if metadata["semantic_unit"] == "failed_check_results"
    ]
    assert issue_indices == list(range(len(issue_indices)))
    assert check_indices == list(range(len(check_indices)))
    assert ids == [
        make_chunk_id(
            "CASE-001",
            str(metadata["semantic_unit"]),
            int(metadata["chunk_index"]),
        )
        for metadata in metadatas
    ]


def test_every_semantic_unit_has_the_specified_priority() -> None:
    assert {
        definition.semantic_unit: definition.priority
        for definition in SEMANTIC_UNIT_DEFINITIONS
    } == {
        "failed_check_results": 100,
        "issue_summary": 90,
        "service_path": 80,
        "core_mib_summary": 70,
        "vendor_specific_mib": 60,
        "upload_mib": 50,
        "full_mib": 10,
    }


def test_all_chunks_from_one_semantic_unit_share_priority() -> None:
    _, _, metadatas = build_chunk_records(
        "CASE-001",
        {"failed_check_results": "abcdefghijklmnop"},
        CharacterTokenizer(),
        6,
        2,
        "CASE-001.md",
        "sample.pcap",
        "Problem summary",
    )

    assert len(metadatas) > 1
    assert {metadata["priority"] for metadata in metadatas} == {100}


def test_flattened_semantic_unit_order_is_preserved() -> None:
    tokenizer = CharacterTokenizer()
    semantic_data = {
        "issue_summary": "abcdefghijk",
        "failed_check_results": "check",
        "core_mib_summary": "core",
    }

    _, _, metadatas = build_chunk_records(
        "CASE-001",
        semantic_data,
        tokenizer,
        6,
        2,
        "CASE-001.md",
        "sample.pcap",
        "Problem summary",
    )

    units = [metadata["semantic_unit"] for metadata in metadatas]
    assert units == [
        "issue_summary",
        "issue_summary",
        "issue_summary",
        "failed_check_results",
        "core_mib_summary",
    ]


def test_empty_semantic_units_are_skipped() -> None:
    tokenizer = CharacterTokenizer()

    ids, documents, metadatas = build_chunk_records(
        "CASE-001",
        {
            "issue_summary": "content",
            "failed_check_results": "   \n",
        },
        tokenizer,
        10,
        2,
        "CASE-001.md",
        "sample.pcap",
        "Problem summary",
    )

    assert ids == ["CASE-001:issue_summary:0"]
    assert documents == ["content"]
    assert [metadata["semantic_unit"] for metadata in metadatas] == [
        "issue_summary"
    ]


def test_paragraph_boundaries_are_preferred() -> None:
    tokenizer = CharacterTokenizer()
    text = "aaaa\n\nbbbb\n\ncccc"

    chunks = split_semantic_unit(text, tokenizer, 10, 2)

    assert [chunk.strip() for chunk in chunks] == ["aaaa", "bbbb", "cccc"]


def test_oversized_paragraph_uses_token_level_splitting() -> None:
    tokenizer = CharacterTokenizer()
    text = "abcdefghijklmno"

    chunks = split_semantic_unit(text, tokenizer, 6, 2)

    assert chunks == ["abcdef", "efghij", "ijklmn", "mno"]


def test_missing_issue_file_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, issue_path, pcap_path, _, _ = prepare_ingest(tmp_path, monkeypatch)
    issue_path.unlink()

    with pytest.raises(RAGIngestError, match="Issue Markdown file not found"):
        ingest_case("CASE-001", issue_path, pcap_path)


def test_missing_capture_file_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, issue_path, pcap_path, _, _ = prepare_ingest(tmp_path, monkeypatch)
    pcap_path.unlink()

    with pytest.raises(RAGIngestError, match="PCAP file not found"):
        ingest_case("CASE-001", issue_path, pcap_path)


def test_unsupported_capture_format_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, issue_path, pcap_path, _, _ = prepare_ingest(tmp_path, monkeypatch)
    unsupported = pcap_path.with_suffix(".txt")
    pcap_path.replace(unsupported)

    with pytest.raises(RAGIngestError, match="Unsupported capture format"):
        ingest_case("CASE-001", issue_path, unsupported)


@pytest.mark.parametrize("case_id", ["", "   ", ".", "..", "../CASE", "a/b", r"a\b"])
def test_unsafe_case_id_is_rejected(
    case_id: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, issue_path, pcap_path, _, _ = prepare_ingest(tmp_path, monkeypatch)

    with pytest.raises(RAGIngestError, match="filename-safe"):
        ingest_case(case_id, issue_path, pcap_path)


def test_ai_dependency_unavailable_has_clear_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import = builtins.__import__

    def fail_ai_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "chromadb":
            raise ImportError("missing chromadb")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_ai_import)

    with pytest.raises(
        RAGIngestError,
        match=r'(?s)AI dependencies are not installed.*omcipcap\[ai\]',
    ):
        rag_ingest._load_ai_dependencies()
