import os
import uvicorn
import logging
import json
import re
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

import chromadb
from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2
import ollama

# ========================
# CONFIG
# ========================

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
NOTES_DIR  = os.path.join(BASE_DIR, "notes")
CHROMA_PATH = os.path.join(BASE_DIR, "chroma_db")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
LLM_MODEL   = os.getenv("LLM_MODEL", "qwen2.5:1.5b")

CHUNK_SIZE    = int(os.getenv("CHUNK_SIZE", "400"))   # chars per chunk
CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "80")) # overlap chars
N_RESULTS     = int(os.getenv("N_RESULTS", "5"))

# ========================
# LOGGING
# ========================

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s  %(message)s")
logger = logging.getLogger(__name__)

# ========================
# APP
# ========================

@asynccontextmanager
async def lifespan(app):
    sync_docs()
    yield

app = FastAPI(title="patchbook", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs(NOTES_DIR, exist_ok=True)
os.makedirs(CHROMA_PATH, exist_ok=True)

# ========================
# EMBEDDINGS — ONNX, no PyTorch
# ========================

embed_fn = ONNXMiniLM_L6_V2()

# ========================
# CHROMA
# ========================

chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_or_create_collection(
    name="wiki",
    embedding_function=embed_fn,
)

# ========================
# CHUNKING
# Splits on paragraph/sentence boundaries with overlap.
# Falls back to hard split only for pathologically long lines.
# ========================

def chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    # Normalise whitespace
    text = text.strip()
    if not text:
        return []

    # Split on blank lines first (paragraph boundary)
    paragraphs = re.split(r"\n{2,}", text)

    chunks: list[str] = []
    buf = ""

    for para in paragraphs:
        para = para.strip()
        if not para:
            continue

        # If para alone is too long, split it on sentence endings
        if len(para) > size:
            sentences = re.split(r"(?<=[.!?])\s+", para)
            for sent in sentences:
                if len(buf) + len(sent) + 1 <= size:
                    buf = (buf + " " + sent).strip()
                else:
                    if buf:
                        chunks.append(buf)
                    # Hard-split sentences that are still too long
                    if len(sent) > size:
                        for i in range(0, len(sent), size - overlap):
                            chunks.append(sent[i : i + size])
                        buf = sent[max(0, len(sent) - overlap):]
                    else:
                        buf = sent
        else:
            if len(buf) + len(para) + 2 <= size:
                buf = (buf + "\n\n" + para).strip()
            else:
                if buf:
                    chunks.append(buf)
                buf = para

    if buf:
        chunks.append(buf)

    # Add overlap: each chunk (except first) prepends tail of previous chunk
    if overlap and len(chunks) > 1:
        overlapped = [chunks[0]]
        for i in range(1, len(chunks)):
            tail = chunks[i - 1][-overlap:]
            overlapped.append(tail + " " + chunks[i])
        return overlapped

    return chunks


# ========================
# INDEXING
# ========================

def sync_docs() -> dict:
    logger.info("Sync started…")

    try:
        existing = collection.get()
        if existing["ids"]:
            collection.delete(ids=existing["ids"])
    except Exception as e:
        logger.warning(f"Clear failed (probably empty): {e}")

    files = [f for f in os.listdir(NOTES_DIR) if f.endswith(".md")]
    total_chunks = 0
    errors = []

    for filename in files:
        filepath = os.path.join(NOTES_DIR, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            chunks = chunk_text(content)
            if not chunks:
                continue

            collection.add(
                documents=chunks,
                metadatas=[
                    {
                        "source": filename,
                        "chunk_index": i,
                        "chunk_preview": chunks[i][:80].replace("\n", " "),
                    }
                    for i in range(len(chunks))
                ],
                ids=[f"{filename}::{i}" for i in range(len(chunks))],
            )
            total_chunks += len(chunks)
            logger.info(f"  {filename}: {len(chunks)} chunks")

        except Exception as e:
            logger.error(f"Error indexing {filename}: {e}")
            errors.append({"file": filename, "error": str(e)})

    result = {
        "files": len(files),
        "chunks": total_chunks,
        "errors": errors,
    }
    logger.info(f"Sync done: {result}")
    return result


# ========================
# ROUTES — static / files
# ========================

@app.get("/")
async def root():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))


@app.get("/sources")
async def get_sources():
    files = [f for f in os.listdir(NOTES_DIR) if f.endswith(".md")]
    return {"sources": [{"source": f, "tags": ["manual"]} for f in sorted(files)]}


@app.get("/file")
async def get_file(name: str):
    file_path = os.path.normpath(os.path.join(NOTES_DIR, name))
    if not file_path.startswith(os.path.abspath(NOTES_DIR) + os.sep):
        return JSONResponse(status_code=403, content={"content": "Access denied"})
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return {"content": f.read()}
    return JSONResponse(status_code=404, content={"content": f"{name} not found"})


# ========================
# ROUTES — ops
# ========================

@app.post("/sync")
async def sync_endpoint():
    """Re-index all .md files in notes/ without restarting."""
    result = sync_docs()
    return result


@app.get("/health")
async def health():
    """System status: index size, model, config."""
    try:
        count = collection.count()
        files = [f for f in os.listdir(NOTES_DIR) if f.endswith(".md")]

        # Check Ollama reachability
        ollama_ok = False
        try:
            c = ollama.Client(host=OLLAMA_HOST)
            c.list()
            ollama_ok = True
        except Exception:
            pass

        return {
            "status": "ok",
            "index": {
                "documents": count,
                "files": len(files),
            },
            "llm": {
                "model": LLM_MODEL,
                "host": OLLAMA_HOST,
                "reachable": ollama_ok,
            },
            "config": {
                "chunk_size": CHUNK_SIZE,
                "chunk_overlap": CHUNK_OVERLAP,
                "n_results": N_RESULTS,
            },
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "detail": str(e)})


# ========================
# OLLAMA STREAMING
# ========================

def stream_ollama(prompt: str):
    client = ollama.Client(host=OLLAMA_HOST)
    stream = client.generate(model=LLM_MODEL, prompt=prompt, stream=True)
    for chunk in stream:
        token = chunk.get("response", "")
        if token:
            yield json.dumps({"token": token}) + "\n"


# ========================
# ROUTE — RAG query
# ========================

@app.post("/query")
async def query(request: Request):
    data = await request.json()
    user_query = data.get("query", "").strip()
    n = int(data.get("n_results", N_RESULTS))
    doc_filter = data.get("source_filter")  # optional: restrict to one file

    if not user_query:
        return JSONResponse(status_code=400, content={"error": "query is required"})

    try:
        where = {"source": doc_filter} if doc_filter else None

        results = collection.query(
            query_texts=[user_query],
            n_results=min(n, max(1, collection.count())),
            where=where,
        )

        docs  = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]

        if not docs:
            def empty_gen():
                yield json.dumps({"token": "Knowledge base is empty. Add .md files to notes/ and call POST /sync."}) + "\n"
                yield json.dumps({"sources": []}) + "\n"
            return StreamingResponse(empty_gen(), media_type="text/plain")

        context = "\n\n---\n\n".join(docs)

        # Deduplicate sources, preserve order
        seen: set[str] = set()
        sources = []
        for m in metas:
            src = m.get("source", "")
            if src not in seen:
                seen.add(src)
                sources.append({
                    "Source": src,
                    "preview": m.get("chunk_preview", ""),
                })

        prompt = f"""You are an engineering assistant. Answer ONLY from the context below.
If the answer is not in the context, say "not found in knowledge base".
Be concise and precise.

Context:
{context}

Question:
{user_query}
"""

        def generator():
            for chunk in stream_ollama(prompt):
                yield chunk
            yield json.dumps({"sources": sources}) + "\n"

        return StreamingResponse(generator(), media_type="text/plain")

    except Exception as e:
        logger.error(e)
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "sources": []},
        )


# ========================
# RUN
# ========================

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9999)
