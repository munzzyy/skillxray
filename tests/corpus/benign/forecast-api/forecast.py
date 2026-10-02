"""Three-day forecast from a public API. No keys, no shell."""

import sys

import requests


def forecast(city: str) -> dict:
    resp = requests.get("https://api.weather.example/v1/forecast",
                        params={"city": city, "days": 3}, timeout=10)
    resp.raise_for_status()
    return resp.json()


if __name__ == "__main__":
    print(forecast(sys.argv[1] if len(sys.argv) > 1 else "Oslo"))
