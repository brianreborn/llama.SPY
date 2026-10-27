# llama.SPY — Metric → SnoopV1 map

Short mapping from llama-server sources into the frozen 64-byte `SnoopV1Frame`.

## Prometheus `GET /metrics` (`llamacpp:*`)

| Source metric | SnoopV1 field | Notes |
|---------------|---------------|-------|
| `llamacpp:predicted_tokens_seconds` | `predicted_tok_s` | Generation tok/s |
| `llamacpp:prompt_tokens_seconds` | `prompt_tok_s` | Prompt/ingest tok/s |
| `llamacpp:requests_processing` | `requests_processing` | Busy request count |
| `llamacpp:requests_deferred` | `requests_deferred` | Deferred queue depth |
| `llamacpp:n_decode_total` | `decode_count` | Truncated to `uint32` |
| `llamacpp:tokens_predicted_total` | *(unused in frame)* | Parsed for future deltas |
| `llamacpp:prompt_tokens_total` | *(unused in frame)* | Parsed for future deltas |

## `GET /slots` (JSON array)

Enabled on llama-server unless `--no-slots`. Each element has `is_processing`.

| Derived | SnoopV1 field | When applied |
|---------|---------------|--------------|
| count(`is_processing` == true) | `requests_processing` | Only if Prometheus lacked that gauge |
| count(`is_processing` == false) | `requests_deferred` | **Deferred-ish** stand-in for idle capacity when Prometheus lacked deferred |

Override URL with `--slots-url`; default is same host/port as `--metrics-url`, path `/slots`.  
`--api-key` sends `Authorization: Bearer …` on both GETs.

## Log timings (`--log-file` / `--backend log`)

| Timing line cue | SnoopV1 field |
|-----------------|---------------|
| `prompt eval` … `tokens per second` | `prompt_tok_s` |
| `eval time` / `… runs … tokens per second` | `predicted_tok_s` |

Stub only: re-reads the file each poll. No FD hijack / stderr steal yet.

## DTrace (FreeBSD primary)

| Probe | SnoopV1 field |
|-------|---------------|
| `llama_decode` return count | `decode_count` |
| duration sum / n | `decode_latency_ns_sum` / `decode_latency_n` |

Tok/s left 0 for the HUD/collector to derive from deltas when desired.
