import os
from dotenv import load_dotenv

load_dotenv()

import re
import math
import json
import base64

from urllib.parse import urlparse
from typing import List, Dict

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import easyocr

# Gemini
from google import genai
from google.genai import types

# ElevenLabs
from elevenlabs.client import ElevenLabs


# ============================================================
# 1. FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="ShieldPlus.AI - Threat Intelligence Backend",
    version="3.0.0",
    description=(
        "OCR + Gemini AI + ElevenLabs based "
        "scam and threat detection backend"
    )
)


# ============================================================
# 2. CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# 3. API KEYS / CLIENT INITIALIZATION
# ============================================================

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY")


# ============================================================
# GEMINI CLIENT
# ============================================================

gemini_client = None

if GEMINI_API_KEY:

    try:

        gemini_client = genai.Client(
            api_key=GEMINI_API_KEY
        )

        print(
            "[INFO] Gemini AI Client Loaded Successfully!"
        )

    except Exception as e:

        print(
            f"[ERROR] Gemini initialization failed: {e}"
        )

else:

    print(
        "[WARNING] GEMINI_API_KEY not found. "
        "Gemini /api/scan will not work."
    )


# ============================================================
# ELEVENLABS CLIENT
# ============================================================

elevenlabs_client = None

if ELEVENLABS_API_KEY:

    try:

        elevenlabs_client = ElevenLabs(
            api_key=ELEVENLABS_API_KEY
        )

        print(
            "[INFO] ElevenLabs Client Loaded Successfully!"
        )

    except Exception as e:

        print(
            f"[ERROR] ElevenLabs initialization failed: {e}"
        )

else:

    print(
        "[WARNING] ELEVENLABS_API_KEY not found. "
        "Voice generation will not work."
    )


# ============================================================
# 4. EASY OCR INITIALIZATION
# ============================================================

print("[INFO] Initializing EasyOCR Engine...")

try:

    reader = easyocr.Reader(
        ["en", "hi"],
        gpu=False
    )

    print(
        "[INFO] EasyOCR Loaded Successfully!"
    )

except Exception as e:

    print(
        f"[ERROR] EasyOCR initialization failed: {e}"
    )

    reader = None


# ============================================================
# 5. CONFIGURATION
# ============================================================

MAX_FILE_SIZE = 10 * 1024 * 1024

ALLOWED_IMAGE_TYPES = {
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
    "image/bmp"
}


# ============================================================
# 6. DOMAIN ENTROPY
# ============================================================

def calculate_domain_entropy(
    domain: str
) -> float:

    if not domain:

        return 0.0

    domain = domain.lower()

    probabilities = [
        domain.count(char) / len(domain)
        for char in set(domain)
    ]

    entropy = -sum(
        p * math.log(p, 2)
        for p in probabilities
        if p > 0
    )

    return round(
        entropy,
        3
    )


# ============================================================
# 7. URL NORMALIZATION
# ============================================================

def normalize_url(
    url: str
) -> str:

    return url.strip(
        " \t\n\r.,!?;:'\"()[]{}<>"
    )


# ============================================================
# 8. DOMAIN EXTRACTION
# ============================================================

def extract_domain(
    url: str
) -> str:

    try:

        normalized = normalize_url(
            url
        )

        if not normalized.startswith(
            ("http://", "https://")
        ):

            normalized = (
                "http://" + normalized
            )

        parsed = urlparse(
            normalized
        )

        return parsed.hostname or ""

    except Exception:

        return ""


# ============================================================
# 9. ENTITY EXTRACTION
# ============================================================

def extract_entities(
    text: str
) -> Dict[str, List[str]]:

    url_pattern = (
        r"(?:https?://|www\.)[^\s]+"
        r"|"
        r"\b[a-zA-Z0-9-]+"
        r"(?:\.[a-zA-Z0-9-]+)+"
        r"(?:/[^\s]*)?"
    )

    upi_pattern = (
        r"\b[a-zA-Z0-9._-]{2,}"
        r"@[a-zA-Z0-9._-]{2,}\b"
    )

    phone_pattern = (
        r"(?<!\d)"
        r"(?:\+91[\s-]?)?"
        r"[6-9]\d{9}"
        r"(?!\d)"
    )

    urls = re.findall(
        url_pattern,
        text,
        flags=re.IGNORECASE
    )

    upis = re.findall(
        upi_pattern,
        text,
        flags=re.IGNORECASE
    )

    phones = re.findall(
        phone_pattern,
        text
    )

    clean_urls = []

    for url in urls:

        url = normalize_url(
            url
        )

        if (
            url
            and url not in clean_urls
        ):

            clean_urls.append(
                url
            )

    clean_upis = []

    for upi in upis:

        upi = upi.lower().strip()

        if upi not in clean_upis:

            clean_upis.append(
                upi
            )

    clean_phones = []

    for phone in phones:

        digits = re.sub(
            r"\D",
            "",
            phone
        )

        if (
            digits.startswith("91")
            and len(digits) == 12
        ):

            digits = digits[2:]

        if (
            len(digits) == 10
            and digits not in clean_phones
        ):

            clean_phones.append(
                digits
            )

    return {

        "extracted_urls":
            clean_urls,

        "extracted_upis":
            clean_upis,

        "extracted_phone_numbers":
            clean_phones
    }


# ============================================================
# 10. URGENCY / SCAM KEYWORDS
# ============================================================

URGENCY_KEYWORDS = [

    # English

    "urgent",
    "immediately",
    "block",
    "blocked",
    "suspended",
    "kyc",
    "lottery",
    "winner",
    "reward",
    "police",
    "digital arrest",
    "refund",
    "expiry",
    "expired",
    "unauthorized",
    "verify now",
    "account will be blocked",
    "click now",
    "pay now",
    "limited time",

    # Hindi / Hinglish

    "turant",
    "abhi",
    "jaldi",
    "inaam",
    "puraskar",
    "jeet gaye",
    "account band",
    "account bandh",
    "kyc update",
    "police case",
    "giraftar",
    "arrest",
    "otp",
    "otp share",
    "link par click",
    "paise bhejo",
    "payment karo"
]


# ============================================================
# 11. SUSPICIOUS DOMAIN KEYWORDS
# ============================================================

SUSPICIOUS_DOMAIN_KEYWORDS = [

    "login",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "kyc",
    "wallet",
    "bank",
    "refund",
    "reward",
    "claim",
    "support",
    "payment",
    "pay"
]


# ============================================================
# 12. RISK SCORING ENGINE
# ============================================================

def run_scoring_engine(
    text: str,
    entities: dict
):

    score = 0

    red_flags = []

    text_lower = text.lower()

    # --------------------------------------------------------
    # A. URGENCY
    # --------------------------------------------------------

    found_urgency = []

    for keyword in URGENCY_KEYWORDS:

        if keyword.lower() in text_lower:

            if keyword not in found_urgency:

                found_urgency.append(
                    keyword
                )

    if found_urgency:

        score += 35

        red_flags.append(
            "Urgency/scam language detected: "
            + ", ".join(found_urgency)
        )

    # --------------------------------------------------------
    # B. URL ANALYSIS
    # --------------------------------------------------------

    for url in entities[
        "extracted_urls"
    ]:

        domain = extract_domain(
            url
        )

        if not domain:

            continue

        domain_lower = domain.lower()

        entropy = calculate_domain_entropy(
            domain
        )

        url_is_long = len(url) > 50

        suspicious_words = [
            word
            for word in SUSPICIOUS_DOMAIN_KEYWORDS
            if word in domain_lower
        ]

        score += 25

        if suspicious_words:

            score += 10

            red_flags.append(
                f"Suspicious domain keywords found in "
                f"{domain}: "
                f"{', '.join(suspicious_words)}"
            )

        if entropy >= 3.8:

            score += 10

            red_flags.append(
                f"High domain entropy detected: "
                f"{domain} ({entropy})"
            )

        if url_is_long:

            score += 5

            red_flags.append(
                f"Unusually long URL detected: {url}"
            )

        if (
            not suspicious_words
            and entropy < 3.8
        ):

            red_flags.append(
                f"External URL detected: {url}"
            )

    # --------------------------------------------------------
    # C. UPI ANALYSIS
    # --------------------------------------------------------

    if entities[
        "extracted_upis"
    ]:

        score += 25

        red_flags.append(
            "UPI/payment handle detected: "
            + ", ".join(
                entities["extracted_upis"]
            )
        )

    # --------------------------------------------------------
    # D. PHONE NUMBER
    # --------------------------------------------------------

    if entities[
        "extracted_phone_numbers"
    ]:

        red_flags.append(
            "Phone number detected: "
            + ", ".join(
                entities[
                    "extracted_phone_numbers"
                ]
            )
        )

    # --------------------------------------------------------
    # E. PAYMENT LANGUAGE
    # --------------------------------------------------------

    payment_keywords = [

        "pay",
        "payment",
        "send money",
        "transfer",
        "upi",
        "otp",
        "bank account",
        "credit card",
        "debit card"
    ]

    found_payment = [
        keyword
        for keyword in payment_keywords
        if keyword in text_lower
    ]

    if found_payment:

        score += 10

        red_flags.append(
            "Financial/payment-related language detected: "
            + ", ".join(found_payment)
        )

    # --------------------------------------------------------
    # F. OTP / CREDENTIAL REQUEST
    # --------------------------------------------------------

    credential_keywords = [

        "otp",
        "password",
        "pin",
        "cvv",
        "card number",
        "account number"
    ]

    found_credentials = [
        keyword
        for keyword in credential_keywords
        if keyword in text_lower
    ]

    if found_credentials:

        score += 15

        red_flags.append(
            "Sensitive credential/OTP request detected: "
            + ", ".join(found_credentials)
        )

    # --------------------------------------------------------
    # G. FINAL SCORE
    # --------------------------------------------------------

    risk_score = min(
        max(score, 0),
        100
    )

    # --------------------------------------------------------
    # H. VERDICT
    # --------------------------------------------------------

    if risk_score >= 70:

        verdict = (
            "CRITICAL THREAT (HIGH RISK)"
        )

    elif risk_score >= 40:

        verdict = (
            "SUSPICIOUS (MEDIUM RISK)"
        )

    else:

        verdict = (
            "SAFE / LOW RISK"
        )

    # --------------------------------------------------------
    # I. NO RED FLAGS
    # --------------------------------------------------------

    if not red_flags:

        red_flags.append(
            "No major scam indicators detected."
        )

    return (
        risk_score,
        verdict,
        red_flags
    )


# ============================================================
# 13. VOICE ALERT SCRIPT
# ============================================================

def generate_voice_alert_script(
    risk_score: int,
    verdict: str,
    red_flags: list
) -> str:

    flags_text = " ".join(
        str(flag).lower()
        for flag in red_flags
    )

    # --------------------------------------------------------
    # BANKING / OTP / PASSWORD
    # --------------------------------------------------------

    if any(
        word in flags_text
        for word in [
            "otp",
            "password",
            "pin",
            "bank",
            "banking",
            "account",
            "credential",
            "financial",
            "payment",
            "card"
        ]
    ):

        if risk_score >= 70:

            return (
                f"सावधान! ShieldPlus Security Alert. "
                f"इस संदेश में OTP, पासवर्ड या बैंकिंग जानकारी "
                f"से जुड़ी संदिग्ध गतिविधि मिली है। "
                f"किसी के साथ OTP, PIN, पासवर्ड या बैंकिंग जानकारी "
                f"शेयर न करें। Risk score {risk_score} percent है।"
            )

        return (
            f"सावधान! इस संदेश में OTP या बैंकिंग जानकारी "
            f"से जुड़े suspicious संकेत मिले हैं। "
            f"किसी के साथ OTP, PIN या पासवर्ड शेयर न करें। "
            f"Risk score {risk_score} percent है।"
        )

    # --------------------------------------------------------
    # JOB / INTERVIEW / EMPLOYMENT
    # --------------------------------------------------------

    if any(
        word in flags_text
        for word in [
            "job",
            "interview",
            "employment",
            "recruitment",
            "salary",
            "vacancy",
            "hiring",
            "career"
        ]
    ):

        return (
            f"सावधान! इस संदेश में job या interview से "
            f"जुड़ी संदिग्ध गतिविधि के संकेत मिले हैं। "
            f"किसी भी job offer के लिए पैसे या personal documents "
            f"शेयर करने से पहले company और sender को verify करें। "
            f"Risk score {risk_score} percent है।"
        )

    # --------------------------------------------------------
    # KYC / IDENTITY VERIFICATION
    # --------------------------------------------------------

    if any(
        word in flags_text
        for word in [
            "kyc",
            "identity",
            "verification",
            "verify",
            "aadhaar",
            "pan",
            "document"
        ]
    ):

        return (
            f"सावधान! इस संदेश में KYC या identity verification "
            f"के नाम पर sensitive information मांगने के संकेत मिले हैं। "
            f"अनजान link पर personal documents या जानकारी शेयर न करें। "
            f"Risk score {risk_score} percent है।"
        )

    # --------------------------------------------------------
    # LINK / PHISHING
    # --------------------------------------------------------

    if any(
        word in flags_text
        for word in [
            "link",
            "url",
            "phishing",
            "website",
            "click"
        ]
    ):

        return (
            f"सावधान! इस संदेश में suspicious link या phishing "
            f"के संकेत मिले हैं। "
            f"अनजान link पर click न करें और sender को verify करें। "
            f"Risk score {risk_score} percent है।"
        )

    # --------------------------------------------------------
    # MONEY / PAYMENT / INVESTMENT
    # --------------------------------------------------------

    if any(
        word in flags_text
        for word in [
            "money",
            "payment",
            "investment",
            "profit",
            "transfer",
            "refund",
            "fee",
            "prize",
            "reward"
        ]
    ):

        return (
            f"सावधान! इस संदेश में पैसे या payment से जुड़ी "
            f"संदिग्ध गतिविधि के संकेत मिले हैं। "
            f"पैसे भेजने या payment करने से पहले जानकारी को verify करें। "
            f"Risk score {risk_score} percent है।"
        )

    # --------------------------------------------------------
    # HIGH RISK - GENERAL
    # --------------------------------------------------------

    if risk_score >= 70:

        return (
            f"सावधान! ShieldPlus Security Alert. "
            f"इस संदेश में high risk scam के संकेत मिले हैं। "
            f"किसी भी link पर click करने, पैसे भेजने या "
            f"sensitive information शेयर करने से पहले रुकें और verify करें। "
            f"Risk score {risk_score} percent है।"
        )

    # --------------------------------------------------------
    # MEDIUM RISK - GENERAL
    # --------------------------------------------------------

    elif risk_score >= 40:

        return (
            f"सावधान! ShieldPlus ने इस संदेश में "
            f"suspicious activity के संकेत पाए हैं। "
            f"कोई भी action लेने से पहले sender और जानकारी को verify करें। "
            f"Risk score {risk_score} percent है।"
        )

    # --------------------------------------------------------
    # LOW RISK
    # --------------------------------------------------------

    else:

        return (
            f"यह संदेश फिलहाल low risk दिखाई देता है। "
            f"फिर भी किसी अनजान व्यक्ति के साथ sensitive information "
            f"शेयर करने से पहले हमेशा verify करें। "
            f"Risk score {risk_score} percent है।"
        )
# ============================================================
# 14. CYBERCRIME COMPLAINT DRAFT
# ============================================================

def generate_cybercrime_complaint_draft(
    raw_text: str,
    entities: dict,
    risk_score: int,
    red_flags: list
) -> dict:

    shortened_text = raw_text[:500]

    return {
        "portal_target":
            "National Cybercrime Reporting Portal / 1930",

        "incident_category":
            "Social Engineering / Financial Fraud Attempt",

        "evidence_summary": {
            "extracted_text":
                raw_text,

            "threat_score":
                f"{risk_score}%",

            "red_flags":
                red_flags,

            "suspect_urls":
                entities["extracted_urls"],

            "suspect_upis":
                entities["extracted_upis"],

            "suspect_phones":
                entities["extracted_phone_numbers"]
        },

        "draft_complaint_text":
            (
                "I am reporting a potentially fraudulent or "
                "suspicious message. The message contains "
                f"the following extracted content: "
                f"'{shortened_text}'. "
                f"Detected URLs: "
                f"{entities['extracted_urls']}. "
                f"Detected UPI handles: "
                f"{entities['extracted_upis']}. "
                f"Detected phone numbers: "
                f"{entities['extracted_phone_numbers']}. "
                f"The automated threat score is "
                f"{risk_score}%."
            )
    }

# ============================================================
# 15. GEMINI AI ANALYSIS
# ============================================================

def run_gemini_analysis(
    extracted_text: str
) -> dict:

    import time

    # --------------------------------------------------------
    # GEMINI CLIENT CHECK
    # --------------------------------------------------------

    if gemini_client is None:

        return {
            "risk_score": 50,

            "verdict":
                "SUSPICIOUS",

            "threat_type":
                "AI analysis unavailable",

            "confidence":
                50,

            "red_flags": [
                "Gemini AI is not configured."
            ],

            "recommended_action": (
                "Do not share OTP, password, PIN "
                "or financial information."
            ),

            "voice_intervention": {
                "voice_script": (
                    "सावधान। कृपया OTP, पासवर्ड, "
                    "PIN या बैंकिंग जानकारी शेयर न करें।"
                )
            }
        }

    # --------------------------------------------------------
    # GEMINI PROMPT
    # --------------------------------------------------------

    prompt = f"""
You are ShieldPlus.AI, a cybersecurity threat
intelligence assistant.

Analyze the following message for scam, phishing,
social engineering, financial fraud, OTP theft,
credential theft, fake KYC, fake police/digital arrest,
malicious links and other cyber threats.

Return ONLY valid JSON.

Required JSON structure:

{{
  "risk_score": 0,
  "verdict": "SAFE / SUSPICIOUS / HIGH RISK",
  "threat_type": "string",
  "confidence": 0,
  "red_flags": [],
  "recommended_action": "string",
  "voice_intervention": {{
      "voice_script": "Hindi warning message"
  }}
}}

Rules:
- risk_score must be between 0 and 100.
- confidence must be between 0 and 100.
- red_flags must be an array of strings.
- voice_script should be short and suitable for Hindi TTS.
- Do not invent URLs, phone numbers or UPI IDs.
- Treat a phone number alone as insufficient proof of fraud.

Message to analyze:

{extracted_text}
"""

    # --------------------------------------------------------
    # GEMINI RETRY SYSTEM
    # --------------------------------------------------------

    for attempt in range(3):

        try:

            print(
                "[GEMINI TEST] Gemini analysis started"
            )

            response = gemini_client.models.generate_content(
                model="gemini-3.8-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json"
                )
            )

            if not response.text:

                raise ValueError(
                    "Gemini returned an empty response."
                )

            scam_data = json.loads(
                response.text
            )

            # ------------------------------------------------
            # RISK SCORE VALIDATION
            # ------------------------------------------------

            scam_data["risk_score"] = max(
                0,
                min(
                    100,
                    int(
                        scam_data.get(
                            "risk_score",
                            50
                        )
                    )
                )
            )

            # ------------------------------------------------
            # CONFIDENCE VALIDATION
            # ------------------------------------------------

            scam_data["confidence"] = max(
                0,
                min(
                    100,
                    int(
                        scam_data.get(
                            "confidence",
                            50
                        )
                    )
                )
            )

            # ------------------------------------------------
            # RED FLAGS VALIDATION
            # ------------------------------------------------

            if not isinstance(
                scam_data.get("red_flags"),
                list
            ):

                scam_data["red_flags"] = []

            return scam_data

        # ----------------------------------------------------
        # INVALID JSON
        # ----------------------------------------------------

        except json.JSONDecodeError:

            print(
                "[GEMINI ERROR] Invalid JSON returned by Gemini"
            )

            if attempt < 2:

                time.sleep(1)

                continue

        # ----------------------------------------------------
        # OTHER GEMINI ERRORS
        # ----------------------------------------------------

        except Exception as e:

            print(
                "[GEMINI ERROR]",
                repr(e)
            )

            error_text = str(e).lower()

            # -----------------------------------------------
            # TEMPORARY SERVER / HIGH DEMAND ERROR
            # -----------------------------------------------

            if (
                "503" in error_text
                or "unavailable" in error_text
                or "high demand" in error_text
            ):

                if attempt < 2:

                    time.sleep(
                        2 ** attempt
                    )

                    continue

            # -----------------------------------------------
            # GENERAL RETRY
            # -----------------------------------------------

            if attempt < 2:

                time.sleep(1)

                continue

    # --------------------------------------------------------
    # GEMINI FALLBACK
    # --------------------------------------------------------

    return {
        "risk_score":
            50,

        "verdict":
            "SUSPICIOUS",

        "threat_type":
            "Potential scam / phishing",

        "confidence":
            60,

        "red_flags": [
            "AI analysis is temporarily unavailable.",
            "Manual verification is recommended.",
            "Do not share OTP, password, PIN or banking information."
        ],

        "recommended_action": (
            "Do not click suspicious links or share "
            "OTP, password, PIN or financial information. "
            "Verify the sender independently."
        ),

        "voice_intervention": {
            "voice_script": (
                "सावधान। AI analysis अभी उपलब्ध नहीं है। "
                "कृपया OTP, पासवर्ड, PIN या बैंकिंग "
                "जानकारी किसी के साथ शेयर न करें।"
            )
        }
    }


# ============================================================
# 16. ELEVENLABS VOICE GENERATION
# ============================================================

def generate_elevenlabs_audio(
    warning_text: str
) -> str:

    if elevenlabs_client is None:

        raise HTTPException(
            status_code=503,
            detail=(
                "ElevenLabs is not configured. "
                "Please set ELEVENLABS_API_KEY."
            )
        )

    if not warning_text:

        warning_text = (
            "सावधान, यह एक स्कैम हो सकता है।"
        )

    try:

        audio_generator = (
            elevenlabs_client.text_to_speech.convert(

                text=warning_text,

                voice_id="JBFqnCBsd6RMkjVDRZzb",

                model_id="eleven_multilingual_v2",

                output_format="mp3_44100_128"
            )
        )

        audio_bytes = b"".join(
            chunk
            for chunk in audio_generator
        )

        audio_base64 = base64.b64encode(
            audio_bytes
        ).decode("utf-8")

        return (
            "data:audio/mp3;base64,"
            + audio_base64
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=(
                "ElevenLabs voice generation failed: "
                + str(e)
            )
        )


# ============================================================
# 17. SCAN REQUEST MODEL
# ============================================================

class ScanRequest(BaseModel):

    extracted_text: str


# ============================================================
# 18. ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():

    return {
        "message":
            "ShieldPlus.AI Backend Systems Online",

        "version":
            "3.0.0",

        "ocr_engine":
            "EasyOCR",

        "ai_engine":
            "Gemini 3.8 Flash",

        "voice_engine":
            "ElevenLabs",

        "supported_languages":
            [
                "English",
                "Hindi"
            ],

        "analysis_endpoint":
            "/api/v1/analyze-threat",

        "ai_scan_endpoint":
            "/api/scan"
    }


# ============================================================
# 19. HEALTH ENDPOINT
# ============================================================

@app.get("/health")
def health():

    return {
        "status":
            "healthy",

        "ocr_loaded":
            reader is not None,

        "gemini_loaded":
            gemini_client is not None,

        "elevenlabs_loaded":
            elevenlabs_client is not None
    }


# ============================================================
# 20. OCR + RULE BASED THREAT ANALYSIS
# ============================================================

@app.post("/api/v1/analyze-threat")
async def analyze_threat(
    file: UploadFile = File(...)
):

    try:

        # ----------------------------------------------------
        # OCR CHECK
        # ----------------------------------------------------

        if reader is None:

            raise HTTPException(
                status_code=503,
                detail="OCR engine is not available."
            )

        # ----------------------------------------------------
        # FILE TYPE CHECK
        # ----------------------------------------------------

        if file.content_type not in ALLOWED_IMAGE_TYPES:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Invalid file type. "
                    "Please upload JPG, PNG, WEBP "
                    "or BMP image."
                )
            )

        # ----------------------------------------------------
        # READ FILE
        # ----------------------------------------------------

        image_bytes = await file.read()

        if not image_bytes:

            raise HTTPException(
                status_code=400,
                detail="Uploaded image is empty."
            )

        # ----------------------------------------------------
        # FILE SIZE CHECK
        # ----------------------------------------------------

        if len(image_bytes) > MAX_FILE_SIZE:

            raise HTTPException(
                status_code=413,
                detail="Image size must be below 10 MB."
            )

        # ----------------------------------------------------
        # OCR
        # ----------------------------------------------------

        ocr_results = reader.readtext(
            image_bytes,
            detail=0
        )

        raw_extracted_text = " ".join(
            str(text).strip()
            for text in ocr_results
            if str(text).strip()
        )

        # ----------------------------------------------------
        # CLEAN OCR TEXT
        # ----------------------------------------------------

        cleaned_text = re.sub(
            r'[^a-zA-Z0-9\s.,!?-@₹]',
            '',
            raw_extracted_text
        )

        if (
            not cleaned_text
            or len(cleaned_text.strip()) < 3
        ):

            cleaned_text = (
                "No readable text detected in image."
            )

        # ----------------------------------------------------
        # ENTITY EXTRACTION
        # ----------------------------------------------------

        entities = extract_entities(
            cleaned_text
        )

        # ----------------------------------------------------
        # RULE BASED SCORING
        # ----------------------------------------------------

        (
            risk_score,
            verdict,
            red_flags
        ) = run_scoring_engine(
            cleaned_text,
            entities
        )

        # ----------------------------------------------------
        # VOICE SCRIPT
        # ----------------------------------------------------

        voice_script = generate_voice_alert_script(
            risk_score,
            verdict,
            red_flags
        )

        # ----------------------------------------------------
        # CYBERCRIME COMPLAINT
        # ----------------------------------------------------

        auto_complaint_draft = (
            generate_cybercrime_complaint_draft(
                cleaned_text,
                entities,
                risk_score,
                red_flags
            )
        )

        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return {

            "status":
                "success",

            "filename":
                file.filename,

            "ocr_extracted_text":
                cleaned_text,

            "threat_intelligence": {

                "risk_score_gauge":
                    f"{risk_score}%",

                "risk_score":
                    risk_score,

                "verdict":
                    verdict,

                "itemized_red_flags":
                    red_flags,

                "parsed_entities":
                    entities
            },

            "voice_synthesis_alert": {

                "provider":
                    "ShieldPlus",

                "status":
                    "script_ready",

                "script":
                    voice_script
            },

            "auto_complaint":
                auto_complaint_draft
        }

    except HTTPException:

        raise

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# 21. TEXT / GEMINI AI SCAN
# ============================================================

@app.post("/api/scan")
async def scan_text(
    request: ScanRequest
):

    try:

        # ----------------------------------------------------
        # GET TEXT
        # ----------------------------------------------------

        text = request.extracted_text.strip()

        if not text:

            raise HTTPException(
                status_code=400,
                detail="Please provide text to analyze."
            )

        # ----------------------------------------------------
        # GEMINI ANALYSIS
        # ----------------------------------------------------

        scam_report = run_gemini_analysis(
            text
        )

        # ----------------------------------------------------
        # VOICE SCRIPT
        # ----------------------------------------------------

        voice_script = ""

        if isinstance(
            scam_report.get(
                "voice_intervention"
            ),
            dict
        ):

            voice_script = (
                scam_report[
                    "voice_intervention"
                ].get(
                    "voice_script",
                    ""
                )
            )

        # ----------------------------------------------------
        # ELEVENLABS AUDIO
        # ----------------------------------------------------

        audio_base64 = None

        if (
            voice_script
            and elevenlabs_client is not None
        ):

            try:

                audio_base64 = (
                    generate_elevenlabs_audio(
                        voice_script
                    )
                )

            except Exception as e:

                print(
                    "[WARNING] ElevenLabs audio generation failed:",
                    e
                )

                audio_base64 = None

        # ----------------------------------------------------
        # FINAL RESPONSE
        # ----------------------------------------------------

        return {

            "success":
                True,

            "status":
                "success",

            "scam_report":
                scam_report,

            "audio_base64":
                audio_base64
        }

    except HTTPException:

        raise

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )