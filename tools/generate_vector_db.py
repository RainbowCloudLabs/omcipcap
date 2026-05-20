#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Sih <daneshih1125@gmail.com>
# Licensed under the MIT License.

import os
import json
import sqlite3
import requests
from pypdf import PdfReader

# local ollama endpoint
OLLAMA_EMBED_URL = "http://localhost:11434/api/embeddings"
EMBED_MODEL = "nomic-embed-text"


DB_PATH = "omci_knowledge_base.db"
SPEC_CONFIG = {
    "ITU-T G.988": {"skip_pages": set(range(0, 6))},
    "ITU-T G.984.3": {"skip_pages": set(range(0, 8))},
    "BBF TR-247": {"skip_pages": set(range(0, 9))},
}


def init_db():
    """initialize DB"""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS knowledge (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,        -- Source document name, e.g., 'G.988', 'TR-247', 'G.984.3'
            chapter TEXT,       -- Target chapter or page identifier, e.g., 'Chapter 7.4', 'Page 45'
            content TEXT,       -- Chunked raw text extracted from the PDF
            embedding TEXT      -- 768-dimensional vector representation stored as a JSON-serialized string
        )
    """)
    conn.commit()
    return conn


def get_embedding(text):
    """Call Ollama to get nomic-embed-text model"""
    payload = {"model": EMBED_MODEL, "prompt": text}
    try:
        response = requests.post(OLLAMA_EMBED_URL, json=payload)
        response.raise_for_status()
        return response.json()["embedding"]
    except Exception as e:
        print(f"[-] Ollama Embedding Error: {e}")
        return None


def process_pdf_to_db(conn, pdf_path, source_name, pages=[]):
    """To read PDF, chunk text, compute embeddings, and write into SQLite."""
    print(f"[*] Parsing {pdf_path}...")
    config = SPEC_CONFIG[source_name]
    reader = PdfReader(pdf_path)
    cursor = conn.cursor()

    for page_num, page in enumerate(reader.pages):
        if page_num in config["skip_pages"]:
            print(f"[-] [Manual Skip] {source_name} - Page {page_num} (Noise/Index)")
            continue
        text = page.extract_text()
        if not text or len(text.strip()) < 50:
            continue

        if len(pages) > 0 and page_num not in pages:
            continue
        tagged_content = f"[{source_name} Page {page_num}] {text.strip()}"

        vector = get_embedding(tagged_content)
        if vector:
            cursor.execute(
                "INSERT INTO knowledge (source, chapter, content, embedding) VALUES (?, ?, ?, ?)",
                (
                    source_name,
                    f"Page {page_num}",
                    tagged_content,
                    json.dumps(vector),
                ),
            )
            print(f"[+] Indexed {source_name} - Page {page_num}")

    conn.commit()


if __name__ == "__main__":
    print("[*] Target model:", EMBED_MODEL)
    db_conn = init_db()

    process_pdf_to_db(db_conn, "G.988.pdf", "ITU-T G.988")
    process_pdf_to_db(db_conn, "TR-247.pdf", "BBF TR-247")
    process_pdf_to_db(db_conn, "G.984.3.pdf", "ITU-T G.984.3", set(range(27, 37)))

    print(f"[+] All done! Vector DB generated at {DB_PATH}")
    db_conn.close()
