# patchbook

Local RAG knowledge base. Drop Markdown files into `notes/`, ask questions in the chat panel.

```
┌─────────────────────────────────────────────────┐
│  notes/*.md  ──►  chunker  ──►  ChromaDB (ONNX) │
│                                        │         │
│  query  ──►  embed  ──►  top-k chunks  │         │
│                              │                   │
│                           prompt  ──►  Ollama    │
│                                        │         │
│                              streamed answer     │
└─────────────────────────────────────────────────┘
```

## Stack

| Layer | Tech |
|---|---|
| API | FastAPI + uvicorn |
| Vector store | ChromaDB (persistent, local) |
| Embeddings | `ONNXMiniLM_L6_V2` via chromadb — **no PyTorch** |
| LLM | Ollama (`qwen2.5:1.5b` default, swap via env) |
| UI | Vanilla HTML/JS, no build step |

## Prerequisites

- [Ollama](https://ollama.ai) running on the host
- Pull the model: `ollama pull qwen2.5:1.5b`
- Docker + Docker Compose

## Run

```bash
cp .env.example .env          # adjust if needed
docker compose up --build
```

Open http://localhost:9999

## Add documents

```bash
cp my-notes.md notes/
```

Then click **↻** (sync button in sidebar) or call:

```bash
curl -X POST http://localhost:9999/sync
```

No restart needed.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | UI |
| `GET` | `/health` | Status: index size, Ollama reachability |
| `GET` | `/sources` | List indexed files |
| `GET` | `/file?name=x.md` | Raw file content |
| `POST` | `/sync` | Re-index `notes/` |
| `POST` | `/query` | RAG query (streaming NDJSON) |

### Query body

```json
{
  "query": "how do I set up OSPF?",
  "n_results": 5,
  "source_filter": "ospf.md"   // optional: restrict to one file
}
```

### Query stream format

Each line is a JSON object, either `{"token": "..."}` or the final `{"sources": [...]}`.

## Config (env vars)

| Var | Default | Description |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama endpoint |
| `LLM_MODEL` | `qwen2.5:1.5b` | Model name |
| `CHUNK_SIZE` | `400` | Max chars per chunk |
| `CHUNK_OVERLAP` | `80` | Overlap between adjacent chunks |
| `N_RESULTS` | `5` | Retrieved chunks per query |

## Chunking strategy

Text is split on paragraph boundaries (`\n\n`), then sentence boundaries if a paragraph is too long, with character-level hard split as last resort. Adjacent chunks share an overlap window to avoid losing context at boundaries.
