# llama.cpp on Containarium

Run the [llama.cpp](https://github.com/ggml-org/llama.cpp) OpenAI-compatible
server with CUDA on a Containarium backend with one command. The `llamacpp`
recipe provisions a dedicated container, starts `llama-server` inside it
serving a HuggingFace GGUF model, and exposes the API on a public hostname.

```bash
containarium recipe deploy llamacpp lc1 \
    --gpu 0 --param hf_repo=ggml-org/gemma-3-1b-it-GGUF --server <gpu-backend>
```

## How it works

A recipe does not run the upstream image *as* the container — Containarium
boxes are LXC system containers. Instead it provisions an Ubuntu LXC with GPU
passthrough and runs the image inside it via Podman (the same pattern the
[Kubeflow recipe](../KUBEFLOW-SETUP.md) uses to run Kubernetes inside an LXC):

```
Incus LXC container  (security.nesting=true, GPU passthrough)
  └── Podman
      └── ghcr.io/ggml-org/llama.cpp:server-cuda  (--device nvidia.com/gpu=all, :8080)
```

The recipe's `post_start` commands run after the container is up:

```
podman volume create llamacpp-models
podman run -d --name llamacpp --restart=always --device nvidia.com/gpu=all \
    -p 8080:8080 -v llamacpp-models:/models \
    ghcr.io/ggml-org/llama.cpp:server-cuda \
    -hf "$CONTAINARIUM_PARAM_HF_REPO" --host 0.0.0.0 --port 8080
```

`llama-server` downloads the GGUF named by `-hf` into the `/models` volume on
first start, so the model survives container restarts.

## Prerequisites

- A Containarium backend with a GPU. Deploy against **that backend's daemon**
  (`--server`); see [Limitations](#limitations).
- A GPU device ID to pass through (`--gpu 0`, a PCI address, etc.).
- **In-container GPU access for Podman.** The recipe runs the container with
  `--device nvidia.com/gpu=all`, which uses Podman's CDI. The GPU backend must
  have the NVIDIA driver and the NVIDIA Container Toolkit (with a generated CDI
  spec) available to the LXC. The `--gpu` flag handles LXC-level passthrough;
  the toolkit inside the box is a one-time operator setup.
- App hosting / routing enabled on the daemon if you want the port exposed on a
  public hostname. Without it the workload still runs and is reachable on the
  LAN; the deploy returns a warning instead of a URL.

## Discover the recipe

`recipe list` and `recipe get` read the catalog compiled into the CLI, so they
work offline without a server:

```bash
containarium recipe list
containarium recipe get llamacpp
```

```
ID:          llamacpp
Name:        llama.cpp server
Image:       ghcr.io/ggml-org/llama.cpp:server-cuda
Requires GPU: true
Resources:   cpu=8 memory=16GB disk=100GB
Port:        8080 -> llamacpp
Volume:      llamacpp-models at /models
Param:       hf_repo [string] default="ggml-org/gemma-3-1b-it-GGUF" (required) — HuggingFace repo to serve, in -hf form.
```

## Deploy

```bash
containarium recipe deploy llamacpp lc1 \
    --gpu 0 \
    --param hf_repo=ggml-org/gemma-3-1b-it-GGUF \
    --server <gpu-backend>
```

| Argument | Meaning |
|---|---|
| `llamacpp` | recipe ID |
| `lc1` | deployment name → container `lc1-container` |
| `--gpu 0` | GPU device to pass through (required; `llamacpp` is a GPU recipe) |
| `--param hf_repo=<repo>` | HuggingFace GGUF repo in `-hf` form (required) |
| `--server <gpu-backend>` | the daemon managing the GPU backend |

Pick any GGUF repo from [HuggingFace](https://huggingface.co/models?library=gguf);
the value is passed straight to `llama-server -hf`. On success the deploy prints
the public URL, e.g. `https://lc1-llamacpp.<base-domain>` (the hostname is
`<name>-<subdomain>` under the daemon's base domain).

## Verify

```bash
# health + model
curl https://lc1-llamacpp.<base-domain>/health

# OpenAI-compatible API
curl https://lc1-llamacpp.<base-domain>/v1/chat/completions \
    -H 'Content-Type: application/json' \
    -d '{"messages":[{"role":"user","content":"hi"}]}'
```

## Via MCP

Agents reach the same code path through the platform MCP server:

```jsonc
// discover
{ "tool": "list_recipes" }

// deploy
{ "tool": "deploy_recipe",
  "arguments": { "recipe_id": "llamacpp", "name": "lc1", "gpu": "0",
                 "parameters": { "hf_repo": "ggml-org/gemma-3-1b-it-GGUF" } } }
```

`deploy_recipe` requires the `containers:write` scope; `list_recipes` requires
`containers:read`.

## Limitations

- **Local backend only (v1).** A recipe deploys on the backend its `--server`
  daemon manages. Targeting a *remote* backend with `--backend-id`/`--pool`
  returns `Unimplemented` rather than running the install on the wrong host. To
  deploy on a specific GPU node, point `--server` at that node's daemon.
- GPU recipes require an explicit `--gpu`; there is no auto-selection of a GPU
  backend yet.

## Cleanup

```bash
containarium delete lc1 --server <gpu-backend>
```
