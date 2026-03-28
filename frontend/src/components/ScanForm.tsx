import { useMemo, useState } from "react";

import { createScan } from "@/services/api";

interface Props {
  onScanCreated: (scanId: string) => void;
}

const DEFAULT_TEMPLATE = {
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "{prompt}" }],
};

const ALL_CATEGORIES = [
  "instruction_override",
  "role_confusion",
  "data_exfiltration",
  "hidden_instruction_extraction",
];

function ScanForm({ onScanCreated }: Props): JSX.Element {
  const [endpointUrl, setEndpointUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [maxPrompts, setMaxPrompts] = useState(100);
  const [timeout, setTimeout] = useState(30);
  const [requestsPerSecond, setRequestsPerSecond] = useState(2);
  const [maxConcurrentRequests, setMaxConcurrentRequests] = useState(5);
  const [selectedCategories, setSelectedCategories] = useState<string[]>(ALL_CATEGORIES);
  const [requestTemplateText, setRequestTemplateText] = useState(
    JSON.stringify(DEFAULT_TEMPLATE, null, 2),
  );
  const [error, setError] = useState<string>("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isReady = useMemo(() => endpointUrl.trim().length > 0, [endpointUrl]);

  const toggleCategory = (category: string): void => {
    setSelectedCategories((prev) =>
      prev.includes(category) ? prev.filter((item) => item !== category) : [...prev, category],
    );
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setError("");

    let parsedTemplate: Record<string, unknown>;
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

    if (selectedCategories.length === 0) {
      setError("Select at least one attack category");
      return;
    }

    setIsSubmitting(true);
    try {
      const response = await createScan({
        target: {
          endpoint_url: endpointUrl,
          api_key: apiKey || undefined,
          request_template: parsedTemplate,
          headers: {},
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
    <section className="panel">
      <h2>Launch Security Scan</h2>
      <p>
        Run a full red-team sweep against your target endpoint using curated prompt injection,
        jailbreak, and leakage probes.
      </p>

      <form onSubmit={handleSubmit}>
        <label>
          Target Endpoint URL
          <input
            placeholder="https://api.example.com/v1/chat/completions"
            value={endpointUrl}
            onChange={(event) => setEndpointUrl(event.target.value)}
            required
          />
        </label>

        <label>
          API Key (optional)
          <input
            placeholder="sk-..."
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
          />
        </label>

        <div className="grid-2">
          <label>
            Max Prompts
            <input
              type="number"
              min={1}
              max={1000}
              value={maxPrompts}
              onChange={(event) => setMaxPrompts(Number(event.target.value))}
            />
          </label>

          <label>
            Timeout (seconds)
            <input
              type="number"
              min={5}
              max={120}
              value={timeout}
              onChange={(event) => setTimeout(Number(event.target.value))}
            />
          </label>
        </div>

        <div className="grid-2">
          <label>
            Requests per second
            <input
              type="number"
              min={1}
              max={20}
              value={requestsPerSecond}
              onChange={(event) => setRequestsPerSecond(Number(event.target.value))}
            />
          </label>

          <label>
            Max concurrent requests
            <input
              type="number"
              min={1}
              max={20}
              value={maxConcurrentRequests}
              onChange={(event) => setMaxConcurrentRequests(Number(event.target.value))}
            />
          </label>
        </div>

        <div>
          <p style={{ marginBottom: 8 }}>Attack Categories</p>
          <div className="grid-2">
            {ALL_CATEGORIES.map((category) => (
              <label key={category} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <input
                  type="checkbox"
                  checked={selectedCategories.includes(category)}
                  onChange={() => toggleCategory(category)}
                />
                {category}
              </label>
            ))}
          </div>
        </div>

        <label>
          Request Template
          <textarea
            value={requestTemplateText}
            onChange={(event) => setRequestTemplateText(event.target.value)}
          />
        </label>

        {error ? <p className="error-text">{error}</p> : null}

        <button type="submit" disabled={!isReady || isSubmitting}>
          {isSubmitting ? "Starting scan..." : "Start scan"}
        </button>
      </form>
    </section>
  );
}

export default ScanForm;
