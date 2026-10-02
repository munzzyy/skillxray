"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
async function forecast(city) {
    const url = "https://api.weather.example/v1/forecast?days=3&city=" + encodeURIComponent(city);
    const res = await fetch(url);
    if (!res.ok) {
        throw new Error("forecast request failed: " + res.status);
    }
    return res.json();
}
forecast(process.argv[2] || "Oslo").then((data) => console.log(JSON.stringify(data)));
