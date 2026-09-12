# ShieldPlus.AI — Hackathon Website

## Run in VS Code

1. Extract this folder.
2. Open the folder in VS Code.
3. Make sure these three files are together:
   - `index.html`
   - `style.css`
   - `script.js`
4. Open `index.html` in your browser.

### Easiest method
Install the **Live Server** extension in VS Code, then right-click `index.html` → **Open with Live Server**.

## What works in this frontend
- Responsive hackathon landing page
- Threat analyzer UI
- Local demo risk scoring using JavaScript heuristics
- Sample scam messages
- Screenshot upload preview
- Risk gauge and red-flag cards
- Browser text-to-speech verdict
- Complaint draft generator
- Architecture, roadmap and team sections
- Scroll animations

## Important
This is a frontend MVP/demo. It does **not** perform real OCR, LLM analysis, ElevenLabs synthesis, FastAPI calls, or automatic submission to a cybercrime portal.

For the hackathon, you can first demonstrate the complete frontend, then connect:
Frontend → FastAPI backend → OCR/LLM scoring → ElevenLabs → response back to frontend.
