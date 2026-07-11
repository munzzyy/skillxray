"""Fetch current weather from a public API. No secrets, no shell."""

import json
import urllib.request


def get_weather(city: str) -> dict:
    url = f"https://api.open-meteo.example/v1/current?city={city}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.load(resp)


if __name__ == "__main__":
    import sys
    print(get_weather(sys.argv[1] if len(sys.argv) > 1 else "London"))
