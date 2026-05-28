# Ollama on Containarium

Run [Ollama](https://ollama.com) with GPU acceleration on a Containarium
backend with one command. The `ollama` recipe provisions a dedicated
container, starts the Ollama server inside it, pulls a model, and exposes the
OpenAI-compatible API on a public hostname.

```bash
containarium recipe deploy ollama ol1 --gpu 0 --param model=llama3 --server <gpu-backend>
```

## How it works

A recipe does not run the upstream image *as* the container — Containarium
boxes are LXC system containers. Instead it provisions an Ubuntu LXC with GPU
passthrough and runs the image inside it via Podman (the same pattern the
[Kubeflow recipe](../KUBEFLOW-SETUP.md) uses to run Kubernetes inside an LXC):

```
Incus LXC container  (security.nesting=true, GPU passthrough)
  └── Podman
      └── ollama/ollama  (--device nvidia.com/gpu=all, :11434)
```

The recipe's `post_start` commands run after the container is up:

```
podman volume create ollama-models
podman run -d --name ollama --restart=always --device nvidia.com/gpu=all \
    -p 11434:11434 -v ollama-models:/root/.ollama docker.io/ollama/ollama
podman exec ollama ollama pull "$CONTAINARIUM_PARAM_MODEL"
```

The model cache lives on a named Podman volume, so it survives container
restarts.

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
containarium recipe get ollama
```

```
ID:          ollama
Name:        Ollama
Image:       ollama/ollama
Requires GPU: true
Resources:   cpu=8 memory=16GB disk=200GB
Port:        11434 -> ollama
Volume:      ollama-models at /root/.ollama
Param:       model [string] default="llama3" — Model to pull after the server starts (e.g. llama3, qwen2.5).
```

## Deploy

```bash
containarium recipe deploy ollama ol1 \
    --gpu 0 \
    --param model=llama3 \
    --server <gpu-backend>
```

| Argument | Meaning |
|---|---|
| `ollama` | recipe ID |
| `ol1` | deployment name → container `ol1-container` |
| `--gpu 0` | GPU device to pass through (required; `ollama` is a GPU recipe) |
| `--param model=<name>` | model to pull on first boot (default `llama3`) |
| `--server <gpu-backend>` | the daemon managing the GPU backend |

On success the deploy prints the public URL, e.g.
`https://ol1-ollama.<base-domain>` (the hostname is `<name>-<subdomain>` under
the daemon's base domain).

## Verify

```bash
# native Ollama API
curl https://ol1-ollama.<base-domain>/api/tags

# OpenAI-compatible API
curl https://ol1-ollama.<base-domain>/v1/chat/completions \
    -H 'Content-Type: application/json' \
    -d '{"model":"llama3","messages":[{"role":"user","content":"hi"}]}'
```

Pull additional models any time over SSH into the box:

```bash
ssh ol1@<host> -- podman exec ollama ollama pull qwen2.5
```

## Via MCP

Agents reach the same code path through the platform MCP server:

```jsonc
// discover
{ "tool": "list_recipes" }

// deploy
{ "tool": "deploy_recipe",
  "arguments": { "recipe_id": "ollama", "name": "ol1", "gpu": "0",
                 "parameters": { "model": "llama3" } } }
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
containarium delete ol1 --server <gpu-backend>
```
