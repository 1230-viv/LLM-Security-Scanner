import { useEffect, useMemo, useState } from "react";

import { createScan } from "@/services/api";

interface Props {
  onScanCreated: (scanId: string) => void;
}

type TemplatePreset = "ollama_generate" | "ollama_chat" | "openai_chat";

interface PresetDefinition {
  label: string;
  hint: string;
  endpoint: string;
  supportsApiKey: boolean;
  headers: Record<string, string>;
  template: (model: string) => Record<string, unknown>;
}

const PRESETS: Record<TemplatePreset, PresetDefinition> = {
  ollama_generate: {
    label: "Ollama Generate API",
    hint: "Ideal for /api/generate prompt completion testing",
    endpoint: "http://localhost:11434/api/generate",
    supportsApiKey: false,
    headers: {},
    template: (model) => ({
      model,
      prompt: "{prompt}",
      stream: false,
      options: {
        temperature: 0.2,
      },
    }),
  },
  ollama_chat: {
    label: "Ollama Chat API",
    hint: "Ideal for /api/chat conversational model testing",
    endpoint: "http://localhost:11434/api/chat",
    supportsApiKey: false,
    headers: {},
    template: (model) => ({
      model,
      stream: false,
      messages: [
        {
          role: "system",
          content: "You are a helpful assistant.",
        },
        {
          role: "user",
          content: "{prompt}",
        },
      ],
    }),
  },
  openai_chat: {
    label: "OpenAI-compatible Chat API",
    hint: "Use this for gateways that implement /v1/chat/completions",
    endpoint: "https://api.openai.com/v1/chat/completions",
    supportsApiKey: true,
    headers: {},
    template: (model) => ({
      model,
      temperature: 0.2,
      messages: [
        {
          role: "system",
          content: "You are a helpful assistant.",
        },
        {
          role: "user",
          content: "{prompt}",
        },
      ],
    }),
  },
};

const ALL_CATEGORIES = [
  "instruction_override",
  "role_confusion",
  "data_exfiltration",
  "hidden_instruction_extraction",
];

function ScanForm({ onScanCreated }: Props): JSX.Element {
  const [preset, setPreset] = useState<TemplatePreset>("ollama_chat");
  const [model, setModel] = useState("llama3.2:latest");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [headersText, setHeadersText] = useState("{}");
  const [maxPrompts, setMaxPrompts] = useState(100);
  const [timeout, setTimeout] = useState(30);
  const [requestsPerSecond, setRequestsPerSecond] = useState(10);
  const [maxConcurrentRequests, setMaxConcurrentRequests] = useState(10);
  const [selectedCategories, setSelectedCategories] = useState<string[]>(ALL_CATEGORIES);
  const [requestTemplateText, setRequestTemplateText] = useState("");
  const [error, setError] = useState<string>("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const activePreset = PRESETS[preset];

  useEffect(() => {
    const defaults = PRESETS[preset];
    setEndpointUrl(defaults.endpoint);
    setHeadersText(JSON.stringify(defaults.headers, null, 2));
    setRequestTemplateText(JSON.stringify(defaults.template(model), null, 2));
    if (!defaults.supportsApiKey) {
      setApiKey("");
    }
  }, [preset]);

  useEffect(() => {
    setRequestTemplateText((previous) => {
      if (!previous.trim()) {
        return previous;
      }

      try {
        const parsed = JSON.parse(previous) as Record<string, unknown>;
        if (typeof parsed.model !== "string") {
          return previous;
        }
        return JSON.stringify({ ...parsed, model }, null, 2);
      } catch {
        return previous;
      }
    });
  }, [model]);

  const isReady = useMemo(
    () => endpointUrl.trim().length > 0 && requestTemplateText.trim().length > 0,
    [endpointUrl, requestTemplateText],
  );

  const toggleCategory = (category: string): void => {
    setSelectedCategories((prev) =>
      prev.includes(category) ? prev.filter((item) => item !== category) : [...prev, category],
    );
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setError("");

    try {
      const parsed = new URL(endpointUrl);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("invalid protocol");
      }
    } catch {
      setError("Target endpoint must be a valid http or https URL");
      return;
    }

    let parsedTemplate: Record<string, unknown>;
    let parsedHeaders: Record<string, string>;

    try {
      parsedTemplate = JSON.parse(requestTemplateText);
    } catch {
      setError("Request template must be valid JSON");
      return;
    }

    if (!requestTemplateText.includes("{prompt}")) {
      setError("Request template must include a {prompt} placeholder");
      return;
    }

    try {
      parsedHeaders = JSON.parse(headersText) as Record<string, string>;
      if (parsedHeaders === null || Array.isArray(parsedHeaders)) {
        throw new Error("headers must be object");
      }

      const hasInvalidValue = Object.values(parsedHeaders).some(
        (value) => typeof value !== "string",
      );
      if (hasInvalidValue) {
        throw new Error("header values must be strings");
      }
    } catch {
      setError("Headers must be a valid JSON object with string values");
      return;
    }

    if (selectedCategories.length === 0) {
      setError("Select at least one attack category");
      return;
    }

    const normalizedTemplate = {
      ...parsedTemplate,
      ...(typeof parsedTemplate.model === "string" ? { model } : {}),
    };

    setIsSubmitting(true);
    try {
      const response = await createScan({
        target: {
          endpoint_url: endpointUrl,
          api_key: activePreset.supportsApiKey && apiKey ? apiKey : undefined,
          request_template: normalizedTemplate,
          headers: parsedHeaders,
          timeout,
        },
        config: {
          max_prompts: maxPrompts,
          categories: selectedCategories,
          timeout,
          rate_limit: { requests_per_second: requestsPerSecond },
          max_concurrent_requests: maxConcurrentRequests,
        },
      });

      onScanCreated(response.scan_id);
    } catch (submissionError) {
      setError(submissionError instanceof Error ? submissionError.message : "Failed to start scan");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section className="card-surface p-5 sm:p-6">
      <div className="flex flex-col gap-3 border-b border-slate-200 pb-4">
        <h2 className="card-heading">Launch Security Scan</h2>
        <p className="muted-copy">
          Configure endpoint, prompt template, and execution budgets. The scanner will execute
          attack prompts and stream progress into the scan dashboard.
        </p>
      </div>

      <form className="mt-5 grid gap-5" onSubmit={handleSubmit}>
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label className="field-label" htmlFor="preset">
              Endpoint Preset
            </label>
            <select
              id="preset"
              className="field-input"
              value={preset}
              onChange={(event) => setPreset(event.target.value as TemplatePreset)}
            >
              {Object.entries(PRESETS).map(([key, value]) => (
                <option key={key} value={key}>
                  {value.label}
                </option>
              ))}
            </select>
            <p className="mt-2 text-xs text-slate-500">{activePreset.hint}</p>
          </div>

          <div>
            <label className="field-label" htmlFor="model">
              Model Name
            </label>
            <input
              id="model"
              className="field-input"
              placeholder="llama3.2:latest"
              value={model}
              onChange={(event) => setModel(event.target.value)}
            />
            <p className="mt-2 text-xs text-slate-500">Applied to template field model when present.</p>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label className="field-label" htmlFor="endpoint">
              Target Endpoint URL
            </label>
            <input
              id="endpoint"
              className="field-input"
              placeholder="http://localhost:11434/api/chat"
              value={endpointUrl}
              onChange={(event) => setEndpointUrl(event.target.value)}
              required
            />
          </div>

          <div>
            <label className="field-label" htmlFor="api-key">
              API Key
            </label>
            <input
              id="api-key"
              className="field-input"
              disabled={!activePreset.supportsApiKey}
              placeholder={activePreset.supportsApiKey ? "sk-..." : "Not required for this preset"}
              value={apiKey}
              onChange={(event) => setApiKey(event.target.value)}
            />
          </div>
        </div>

        <div className="grid gap-4 rounded-2xl border border-slate-200 bg-slate-50 p-4 md:grid-cols-2 lg:grid-cols-4">
          <div>
            <label className="field-label" htmlFor="max-prompts">
              Max Prompts
            </label>
            <input
              id="max-prompts"
              className="field-input"
              type="number"
              min={1}
              max={1000}
              value={maxPrompts}
              onChange={(event) => setMaxPrompts(Number(event.target.value))}
            />
          </div>

          <div>
            <label className="field-label" htmlFor="timeout">
              Timeout Seconds
            </label>
            <input
              id="timeout"
              className="field-input"
              type="number"
              min={5}
              max={120}
              value={timeout}
              onChange={(event) => setTimeout(Number(event.target.value))}
            />
          </div>

          <div>
            <label className="field-label" htmlFor="rps">
              Requests Per Second
            </label>
            <input
              id="rps"
              className="field-input"
              type="number"
              min={1}
              max={20}
              value={requestsPerSecond}
              onChange={(event) => setRequestsPerSecond(Number(event.target.value))}
            />
          </div>

          <div>
            <label className="field-label" htmlFor="concurrency">
              Max Concurrency
            </label>
            <input
              id="concurrency"
              className="field-input"
              type="number"
              min={1}
              max={20}
              value={maxConcurrentRequests}
              onChange={(event) => setMaxConcurrentRequests(Number(event.target.value))}
            />
          </div>
        </div>

        <div>
          <p className="field-label mb-3">Attack Categories</p>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            {ALL_CATEGORIES.map((category) => {
              const selected = selectedCategories.includes(category);
              return (
                <button
                  key={category}
                  type="button"
                  onClick={() => toggleCategory(category)}
                  className={`rounded-xl border px-3 py-2 text-left text-sm font-medium transition ${
                    selected
                      ? "border-slate-900 bg-slate-900 text-white"
                      : "border-slate-300 bg-white text-slate-700 hover:border-slate-500"
                  }`}
                >
                  {category}
                </button>
              );
            })}
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <div>
            <label className="field-label" htmlFor="headers">
              Request Headers JSON
            </label>
            <textarea
              id="headers"
              className="field-input code-scroll min-h-40 font-mono text-xs leading-5"
              value={headersText}
              onChange={(event) => setHeadersText(event.target.value)}
            />
          </div>

          <div>
            <label className="field-label" htmlFor="template">
              Request Template JSON
            </label>
            <textarea
              id="template"
              className="field-input code-scroll min-h-40 font-mono text-xs leading-5"
              value={requestTemplateText}
              onChange={(event) => setRequestTemplateText(event.target.value)}
            />
            <p className="mt-2 text-xs text-slate-500">
              Include at least one string with placeholder {"{prompt}"} so attack prompts can be
              injected.
            </p>
          </div>
        </div>

        {error ? (
          <p className="rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </p>
        ) : null}

        <div className="flex flex-col items-start justify-between gap-3 sm:flex-row sm:items-center">
          <p className="text-xs text-slate-500">
            Start a scan to open a live progress page with findings, severity filters, and report
            export.
          </p>
          <button
            type="submit"
            disabled={!isReady || isSubmitting}
            className="rounded-xl bg-gradient-to-r from-slate-900 to-slate-700 px-5 py-2.5 text-sm font-semibold text-white transition hover:from-slate-800 hover:to-slate-600 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isSubmitting ? "Starting scan..." : "Start scan"}
          </button>
        </div>
      </form>
    </section>
  );
}

export default ScanForm;
