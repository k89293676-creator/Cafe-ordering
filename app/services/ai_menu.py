"""AI menu item suggestions via Google Gemini.

Usage from routes::

    from app.services.ai_menu import suggest_menu_items
    items = suggest_menu_items(api_key, cuisine, price_range)
    # items → [{"name": str, "description": str, "price": str}, ...]

Only active when GEMINI_API_KEY is set in environment.
"""
from __future__ import annotations

import json
import logging

log = logging.getLogger("cafe.ai_menu")


def suggest_menu_items(api_key: str, cuisine: str, price_range: str) -> list[dict]:
    """Call Gemini 1.5 Flash and return a flat list of menu item suggestions.

    Args:
        api_key:     Gemini API key.
        cuisine:     Free-text cuisine / café style (e.g. "Italian", "Brunch").
        price_range: One of "budget", "mid-range", or "premium".

    Returns:
        List of dicts with keys ``name``, ``description``, ``price`` (string).

    Raises:
        RuntimeError: If the API key is missing, the package is not installed,
                      or the API call fails.
    """
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not configured.")

    prompt = (
        f"You are a professional café menu consultant. "
        f"Suggest 6 to 8 menu items for a {cuisine} café with a {price_range} price range. "
        f"Return ONLY valid JSON — an array of objects with exactly these keys: "
        f'"name" (string), "description" (one sentence, max 15 words), "price" (string like "£4.50"). '
        f"No markdown, no explanation, no extra keys. Example: "
        f'[{{"name":"Flat White","description":"Velvety espresso with steamed whole milk.","price":"£3.50"}}]'
    )

    try:
        import google.generativeai as genai  # type: ignore

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        raw = (response.text or "").strip()

        # Strip markdown code fences if present
        if raw.startswith("```"):
            lines = raw.split("\n")
            inner = lines[1:] if len(lines) > 1 else lines
            if inner and inner[-1].strip() == "```":
                inner = inner[:-1]
            raw = "\n".join(inner)

        data = json.loads(raw)

        if isinstance(data, dict):
            # Tolerate {items: [...]} or {suggestions: [...]}
            for key in ("items", "suggestions", "menu"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
            else:
                # Single object wrapped in dict — unlikely but handle it
                data = [data]

        if not isinstance(data, list):
            raise ValueError(f"Unexpected Gemini response type: {type(data)}")

        cleaned: list[dict] = []
        for item in data:
            if isinstance(item, dict) and "name" in item:
                cleaned.append({
                    "name": str(item.get("name", "")),
                    "description": str(item.get("description", "")),
                    "price": str(item.get("price", "")),
                })
        return cleaned

    except ImportError:
        log.error("google-generativeai package not installed.")
        raise RuntimeError(
            "AI suggestions require the google-generativeai package. "
            "Install it with: pip install google-generativeai"
        )
    except json.JSONDecodeError as exc:
        log.error("Gemini returned non-JSON: %s", exc)
        raise RuntimeError("AI returned an unexpected format. Please try again.")
    except Exception as exc:
        log.error("Gemini API error: %s", exc)
        raise RuntimeError(f"AI suggestion failed: {exc}")
