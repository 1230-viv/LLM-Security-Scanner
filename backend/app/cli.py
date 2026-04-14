from __future__ import annotations

import json
import os

import httpx
import typer
from rich.console import Console

from app.attack_library.repository import AttackPromptRepository

app = typer.Typer(help="LLM Security Scanner CLI")
console = Console()


def _api_base() -> str:
    return os.getenv("SCANNER_API_BASE", "http://localhost:8000/api/v1").rstrip("/")


def _headers() -> dict[str, str]:
    token = os.getenv("SCANNER_API_TOKEN", "change-me")
    return {"X-Scanner-Token": token, "Content-Type": "application/json"}


@app.command()
def scan(
    endpoint_url: str = typer.Argument(..., help="Target endpoint URL"),
    api_key: str = typer.Option("", "--api-key", help="Target endpoint API key"),
    model: str = typer.Option("gpt-4o-mini", "--model", help="Model name inserted in request payload"),
    template_preset: str = typer.Option(
        "chat",
        "--template-preset",
        help="Request template preset: chat or generate",
    ),
    max_prompts: int = typer.Option(50, "--max-prompts", min=1, max=1000),
    requests_per_second: float = typer.Option(
        10.0,
        "--requests-per-second",
        min=0.1,
        max=20.0,
        help="Client-side request rate target",
    ),
    max_concurrent_requests: int = typer.Option(
        10,
        "--max-concurrent-requests",
        min=1,
        max=20,
        help="Maximum in-flight requests",
    ),
    timeout: int = typer.Option(
        30,
        "--timeout",
        min=5,
        max=120,
        help="Per-request timeout in seconds",
    ),
    categories: str = typer.Option(
        "instruction_override,role_confusion,data_exfiltration,hidden_instruction_extraction",
        "--categories",
        help="Comma-separated categories",
    ),
) -> None:
    if template_preset == "chat":
        request_template = {
            "model": model,
            "messages": [{"role": "user", "content": "{prompt}"}],
        }
    elif template_preset == "generate":
        request_template = {
            "model": model,
            "prompt": "{prompt}",
            "stream": False,
        }
    else:
        raise typer.BadParameter("--template-preset must be one of: chat, generate")

    payload = {
        "target": {
            "endpoint_url": endpoint_url,
            "api_key": api_key or None,
            "request_template": request_template,
            "headers": {},
            "timeout": timeout,
        },
        "config": {
            "max_prompts": max_prompts,
            "categories": [item.strip() for item in categories.split(",") if item.strip()],
            "timeout": timeout,
            "rate_limit": {"requests_per_second": requests_per_second},
            "max_concurrent_requests": max_concurrent_requests,
        },
    }

    response = httpx.post(f"{_api_base()}/scan", headers=_headers(), json=payload, timeout=30)
    response.raise_for_status()
    body = response.json()
    console.print(f"[green]Scan queued[/green] id={body['scan_id']}")


@app.command()
def status(scan_id: str = typer.Argument(..., help="Scan ID")) -> None:
    response = httpx.get(f"{_api_base()}/scan/{scan_id}", headers=_headers(), timeout=30)
    response.raise_for_status()
    console.print_json(data=response.json())


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan ID"),
    format: str = typer.Option("json", "--format", help="json or markdown"),
) -> None:
    response = httpx.get(
        f"{_api_base()}/report/{scan_id}",
        headers=_headers(),
        params={"format": format},
        timeout=30,
    )
    response.raise_for_status()

    if format == "markdown":
        console.print(response.text)
        return

    console.print_json(data=response.json())


@app.command("list-categories")
def list_categories() -> None:
    repository = AttackPromptRepository()
    categories = repository.get_categories()
    console.print(json.dumps(categories, indent=2))


if __name__ == "__main__":
    app()
