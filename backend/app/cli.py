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
    max_prompts: int = typer.Option(50, "--max-prompts", min=1, max=1000),
    categories: str = typer.Option(
        "instruction_override,role_confusion,data_exfiltration,hidden_instruction_extraction",
        "--categories",
        help="Comma-separated categories",
    ),
) -> None:
    payload = {
        "target": {
            "endpoint_url": endpoint_url,
            "api_key": api_key or None,
            "request_template": {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "{prompt}"}],
            },
            "headers": {},
            "timeout": 30,
        },
        "config": {
            "max_prompts": max_prompts,
            "categories": [item.strip() for item in categories.split(",") if item.strip()],
            "timeout": 30,
            "rate_limit": {"requests_per_second": 2},
            "max_concurrent_requests": 5,
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
