# Cernis container submission template

The Python-entrypoint flavor of the Cernis benchmark imports your
`submission.py` in-process and trusts it. The container flavor — this
template — runs your submission inside an isolated docker container
with no network and a read-only rootfs.

```
docker run --rm --network=none --read-only \
    --tmpfs /tmp:rw,size=512m \
    --memory=4g --cpus=2 \
    --cap-drop=ALL --security-opt=no-new-privileges \
    -v <in>:/in:ro -v <out>:/out:rw \
    your-submission-image
```

The Cernis runner sets `<in>` and `<out>` for you. Your container reads
`/in/eval_features.jsonl` and writes `/out/scores.jsonl`. That's the
whole contract.

## Layout

```
submission_container/
├── Dockerfile        # what to build
├── requirements.txt  # your deps; reference is empty
├── runner.py         # I/O wrapper — DO NOT EDIT
├── submission.py     # YOUR predict() (+ optional train())
└── README.md         # this file
```

`runner.py` is the I/O wrapper that reads/writes the JSONL files and
calls your `predict()`. Don't edit it — every container submission
ships the same wrapper so the contract is uniform across submitters.

`submission.py` is yours. Replace it with your model. The signature is
the same as the Python-entrypoint flavor:

```python
def predict(features: list[dict]) -> list[dict]:
    """One row per input session_id, each with agent_score ∈ [0, 1]."""
    ...

def train(train_features: list[dict], dev_features: list[dict]) -> None:
    """Optional. If defined and the runner finds train_features.jsonl
    in /in, called before predict. Persist any state to module-level
    variables — the runner imports submission once per container run."""
    ...
```

See `benchmark/SUBMISSION.md` for the public feature schema (`agg`,
`seq`, `hp`, etc.) and the held-back truth fields.

## Build + test locally

```sh
# 1. Build the image
docker build -t my-cernis-submission .

# 2. Smoke-test against any features.jsonl you have lying around.
#    The Cernis runner does this for you in production; this is just
#    to confirm your container works end-to-end.
mkdir -p /tmp/cernis-test/in /tmp/cernis-test/out
cat > /tmp/cernis-test/in/eval_features.jsonl <<'EOF'
{"session_id": "test-1", "target_app": "dvwa", "agg": [10, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1000], "seq": [[1, 200, 0, 0, 100, 200, 0.3, 4, 0]], "hp": [0, 0, 0, 0]}
EOF
chmod 777 /tmp/cernis-test/out

docker run --rm --network=none --read-only \
    --tmpfs /tmp:rw,size=512m \
    --memory=4g --cpus=2 \
    --cap-drop=ALL --security-opt=no-new-privileges \
    -v /tmp/cernis-test/in:/in:ro \
    -v /tmp/cernis-test/out:/out:rw \
    my-cernis-submission

cat /tmp/cernis-test/out/scores.jsonl
# → {"agent_score": 0.9, "session_id": "test-1"}
```

## What the reference submission does

The shipped `submission.py` scores by the modal User-Agent bucket
(column 6 of the per-request feature vector — see
`detector/features.py::_req_features`). Sessions whose dominant UA is
`curl` / `python` / `wget` score high (0.90); browser-driven sessions
score low. It's a literal floor baseline — your real model should beat
it comfortably.

## Resource accounting

The Cernis runner measures your container's wall-time, peak memory
(via background `docker stats` polling), and exit code. These show up
on the leaderboard alongside PR-AUC and FP/hour. A submission that
hits the same PR-AUC at 1/10th the wall-time is meaningfully better,
and the leaderboard surfaces that.

## What the harness will reject

- `--network none` is enforced — any attempt to fetch a model at
  predict-time fails the container.
- The rootfs is read-only — pre-bake every weight + dep into the
  image at build time.
- Memory cap kills the container if you exceed it. Default is 4 GB.
- Missing rows / extra rows / out-of-`[0, 1]` `agent_score` /
  duplicate `session_id` all fail post-run validation.
- Any field named `accuracy` in `scores.jsonl` fails the run.
  Cernis reports PR-AUC and FP/hour; accuracy is structurally
  forbidden across the project.
