// Thin client for Google Gemini's free-tier API. Used to power the
// "高情商回復" (high-EQ response) parent coaching feature. Kept isolated
// in its own module so the rest of the app doesn't need to know which AI
// provider is behind it.

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.0-flash";

function isConfigured() {
  return !!GEMINI_API_KEY;
}

// messages: [{ role: 'user' | 'model', text: '...' }, ...]
// opts.json: true -> ask Gemini to return raw JSON text (still returned as a string; caller parses it)
async function callGemini(systemPrompt, messages, opts = {}) {
  if (!GEMINI_API_KEY) {
    const err = new Error("GEMINI_API_KEY not configured");
    err.code = "NO_API_KEY";
    throw err;
  }

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;
  const body = {
    system_instruction: { parts: [{ text: systemPrompt }] },
    contents: messages.map((m) => ({ role: m.role, parts: [{ text: m.text }] })),
    generationConfig: opts.json ? { response_mime_type: "application/json" } : {}
  };

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => "");
    const err = new Error(`Gemini API error ${res.status}: ${errText}`);
    err.code = "API_ERROR";
    throw err;
  }

  const data = await res.json();
  const text =
    data &&
    data.candidates &&
    data.candidates[0] &&
    data.candidates[0].content &&
    data.candidates[0].content.parts
      ? data.candidates[0].content.parts.map((p) => p.text || "").join("")
      : "";
  return text;
}

module.exports = { callGemini, isConfigured };
