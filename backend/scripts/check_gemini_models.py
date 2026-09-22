"""Find which Gemini models actually work with your key right now.

Run from the backend folder:   python -m scripts.check_gemini_models

1. Lists the text models your key can use for generating answers
2. Sends each Flash model one tiny request ("Reply with OK")
3. Prints which ones answered, how fast, and the exact error for the rest

This uses one free request per model tested (about 5 to 10 in total).
"""
import time

import httpx2

from app.config import get_settings

BASE = "https://generativelanguage.googleapis.com/v1beta"
SKIP_WORDS = ("tts", "audio", "image", "embedding", "live", "native")


def main() -> None:
    settings = get_settings()
    if not settings.gemini_api_key:
        print("GEMINI_API_KEY is not set in backend/.env")
        return
    headers = {"x-goog-api-key": settings.gemini_api_key}

    with httpx2.Client(timeout=30, headers=headers) as client:
        response = client.get(f"{BASE}/models", params={"pageSize": 1000})
        response.raise_for_status()
        models = [
            m["name"].removeprefix("models/")
            for m in response.json().get("models", [])
            if "generateContent" in m.get("supportedGenerationMethods", [])
            and "flash" in m["name"]
            and not any(word in m["name"] for word in SKIP_WORDS)
        ]
        print(f"Flash text models your key can call: {', '.join(models) or 'none'}\n")
        print(f"Currently configured: GEMINI_MODEL={settings.gemini_model!r}\n")

        for name in models:
            started = time.perf_counter()
            try:
                reply = client.post(
                    f"{BASE}/models/{name}:generateContent",
                    json={"contents": [{"role": "user", "parts": [{"text": "Reply with the single word OK."}]}]},
                    timeout=30,
                )
            except httpx2.TimeoutException:
                print(f"[ TIMEOUT ] {name}: no answer within 30 seconds")
                continue
            except httpx2.RequestError as exc:
                print(f"[ NO CONN ] {name}: {type(exc).__name__}")
                continue
            seconds = time.perf_counter() - started
            if reply.status_code == 200:
                print(f"[  WORKS  ] {name}  ({seconds:.1f} s)")
            else:
                try:
                    message = reply.json().get("error", {}).get("message", "")
                except Exception:
                    message = ""
                print(f"[ HTTP {reply.status_code} ] {name}: {' '.join(message.split())[:160]}")

    print("\nPick a model marked WORKS for GEMINI_MODEL, preferably the fastest stable one"
          " (names without 'preview' or 'latest').")


if __name__ == "__main__":
    main()
