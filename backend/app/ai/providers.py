"""The AI services ThreatLens can use to write reports.

Both providers return the same thing: the model's text plus token counts.
If one fails for any reason, the report writer moves on to the next.
"""
from dataclasses import dataclass

import httpx2

from app.config import Settings

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


class ProviderError(Exception):
    """A provider couldn't produce an answer. The message is safe to show users.

    retryable=True means the problem is probably temporary on the provider's side
    (overloaded or a brief server error), so trying once more is worthwhile.
    """

    def __init__(self, message: str, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


@dataclass
class Completion:
    text: str
    input_tokens: int | None
    output_tokens: int | None


class Provider:
    name = ""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def model(self) -> str:
        raise NotImplementedError

    def is_configured(self) -> bool:
        raise NotImplementedError

    async def complete(self, system: str, user: str, client: httpx2.AsyncClient) -> Completion:
        raise NotImplementedError


def _error_detail(response: httpx2.Response) -> str:
    """The provider's own explanation, e.g. 'models/x is not found for API version v1beta'."""
    try:
        message = (response.json().get("error") or {}).get("message") or ""
    except Exception:
        message = ""
    message = " ".join(str(message).split())
    return f": {message[:200]}" if message else ""


def _raise_for_status(response: httpx2.Response, name: str) -> None:
    code = response.status_code
    if code < 400:
        return
    detail = _error_detail(response)
    if code == 429:
        raise ProviderError(f"{name} rate limit or daily quota reached{detail}")
    if code in (401, 403):
        raise ProviderError(f"{name} refused the API key (HTTP {code}){detail}")
    if code == 404:
        raise ProviderError(f"{name} doesn't recognize the model name (HTTP 404){detail}")
    if code in (500, 502, 503, 504):
        raise ProviderError(f"{name} was busy or had a server error (HTTP {code}){detail}", retryable=True)
    raise ProviderError(f"{name} returned HTTP {code}{detail}")


class GeminiProvider(Provider):
    name = "Gemini"

    @property
    def model(self) -> str:
        return self.settings.gemini_model

    def is_configured(self) -> bool:
        return bool(self.settings.gemini_api_key and self.settings.gemini_model)

    async def complete(self, system: str, user: str, client: httpx2.AsyncClient) -> Completion:
        response = await client.post(
            GEMINI_URL.format(model=self.model),
            headers={"x-goog-api-key": self.settings.gemini_api_key},
            json={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {"responseMimeType": "application/json", "maxOutputTokens": 8192},
            },
            timeout=self.settings.ai_timeout_seconds,
        )
        _raise_for_status(response, self.name)
        body = response.json()
        candidates = body.get("candidates") or []
        if not candidates:
            reason = (body.get("promptFeedback") or {}).get("blockReason", "no answer")
            raise ProviderError(f"Gemini returned no answer ({reason})")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
        if not text.strip():
            raise ProviderError(f"Gemini returned an empty answer ({candidates[0].get('finishReason', 'unknown')})")
        usage = body.get("usageMetadata") or {}
        return Completion(text, usage.get("promptTokenCount"), usage.get("candidatesTokenCount"))


class GroqProvider(Provider):
    name = "Groq"

    @property
    def model(self) -> str:
        return self.settings.groq_model

    def is_configured(self) -> bool:
        return bool(self.settings.groq_api_key and self.settings.groq_model)

    async def complete(self, system: str, user: str, client: httpx2.AsyncClient) -> Completion:
        response = await client.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {self.settings.groq_api_key}"},
            json={
                "model": self.model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "response_format": {"type": "json_object"},
                "temperature": 0.2,
                "max_completion_tokens": 4096,
            },
            timeout=self.settings.ai_timeout_seconds,
        )
        _raise_for_status(response, self.name)
        body = response.json()
        choices = body.get("choices") or []
        text = ((choices[0].get("message") or {}).get("content") or "") if choices else ""
        if not text.strip():
            raise ProviderError("Groq returned an empty answer")
        usage = body.get("usage") or {}
        return Completion(text, usage.get("prompt_tokens"), usage.get("completion_tokens"))


def providers_in_order(settings: Settings) -> list[Provider]:
    """Providers in the order set by AI_PROVIDER_ORDER (unknown names are ignored)."""
    by_name = {"gemini": GeminiProvider, "groq": GroqProvider}
    chosen = [by_name[n] for n in
              (part.strip().lower() for part in settings.ai_provider_order.split(","))
              if n in by_name]
    for cls in by_name.values():  # anything left out still acts as a last resort
        if cls not in chosen:
            chosen.append(cls)
    return [cls(settings) for cls in chosen]
