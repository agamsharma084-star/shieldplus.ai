const BACKEND_URL = "http://127.0.0.1:8000";

const samples = {
  bank: "URGENT: Your bank KYC is suspended. Your account will be blocked today. Verify immediately using this link: http://secure-kyc-example.com/verify. Share the OTP to complete verification.",
  task: "Congratulations! You have been selected for a work-from-home task. Deposit ₹2,000 to unlock your first task and earn ₹8,000 today. Act now — limited slots!",
  qr: "Your payment is waiting. Scan this QR code to receive your refund. Complete it within 10 minutes or the transaction will be cancelled. Send a screenshot after payment."
};

const $ = (id) => document.getElementById(id);

let latestAudio = null;
let latestVoiceScript = "";

function calculateRisk(text) {
  const t = text.toLowerCase();
  let score = 8;
  const flags = [];

  const rules = [
    {
      keys: ["urgent", "immediately", "today", "act now", "within 10 minutes", "limited"],
      points: 22,
      title: "Urgency / pressure trigger",
      desc: "The message creates time pressure to reduce careful decision-making."
    },
    {
      keys: ["otp", "pin", "password", "cvv", "share the otp"],
      points: 28,
      title: "Sensitive credential request",
      desc: "Requests for OTPs, PINs or similar secrets are a strong warning sign."
    },
    {
      keys: ["kyc", "refund", "account will be blocked", "verify"],
      points: 17,
      title: "Impersonation / verification theme",
      desc: "Common scam narratives use KYC, refunds or account-blocking threats."
    },
    {
      keys: ["deposit", "pay", "payment", "₹", "upi", "qr", "transfer"],
      points: 16,
      title: "Payment request",
      desc: "The message attempts to move money or induce a payment action."
    },
    {
      keys: ["http://", "https://", "bit.ly", "tinyurl", "login"],
      points: 15,
      title: "Suspicious link / login cue",
      desc: "Links or login language should be verified independently before use."
    },
    {
      keys: ["work-from-home", "task", "earn", "selected"],
      points: 13,
      title: "Fake task / job pattern",
      desc: "Easy-money task narratives can be used to push victims toward deposits."
    }
  ];

  rules.forEach((r) => {
    if (r.keys.some((k) => t.includes(k))) {
      score += r.points;
      flags.push({
        title: r.title,
        desc: r.desc
      });
    }
  });

  if (flags.length === 0) {
    flags.push({
      title: "No strong demo signals found",
      desc: "This does not prove a message is safe. Verify the sender and destination independently."
    });
  }

  score = Math.min(99, score);

  return {
    score,
    flags: flags.slice(0, 4)
  };
}


function renderResult(score, flags) {
  $("riskScore").textContent = score + "%";
  $("heroRisk").textContent = score + "%";
  $("meterFill").style.width = score + "%";

  $("resultStatus").textContent =
    score >= 65 ? "HIGH RISK" :
    score >= 35 ? "CAUTION" :
    "LOWER RISK";

  $("resultStatus").className =
    "chip " + (score >= 65 ? "" : "neutral");

  $("verdictTitle").textContent =
    score >= 65
      ? "Likely social-engineering scam"
      : score >= 35
      ? "Suspicious — verify first"
      : "No strong scam pattern found";

  $("verdictText").textContent =
    score >= 65
      ? "Do not click unknown links, share OTP/PIN details, or send money based only on this message."
      : "Treat the result as a signal, not proof. Confirm the sender through a trusted channel.";

  $("flags").innerHTML = flags.map((f) => `
    <div class="flag">
      <div class="flag-icon">⚠</div>
      <div>
        <strong>${f.title}</strong>
        <small>${f.desc}</small>
      </div>
    </div>
  `).join("");

  $("voiceBtn").disabled = false;
}


/* ================================
   GEMINI + BACKEND TEXT ANALYSIS
================================ */

async function analyzeTextWithBackend(text) {
  try {
    /*
      Local rule score = Voice / Rule Risk
      This keeps Voice Risk separate from Gemini Risk.
    */
    const localResult = calculateRisk(text);
    window.ocrRiskScore = localResult.score;

    $("resultStatus").textContent = "ANALYZING...";
    $("resultStatus").className = "chip neutral";

    $("voiceAnalysisCard").classList.remove("hidden");
    $("geminiAnalysisCard").classList.remove("hidden");

    $("voiceAnalysisStatus").textContent = "ANALYZING...";
    $("geminiAnalysisStatus").textContent = "ANALYZING...";

    const response = await fetch(`${BACKEND_URL}/api/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        extracted_text: text
      })
    });

    if (!response.ok) {
      throw new Error("Backend returned HTTP " + response.status);
    }

    const data = await response.json();

    const report = data.scam_report || {};

    /* -------------------------
       SEPARATE SCORES
    ------------------------- */

    const geminiScore = Number(report.risk_score ?? 0);

    const voiceScore = Number(
      window.ocrRiskScore ?? localResult.score
    );

    const overallScore = Math.round(
      (geminiScore + voiceScore) / 2
    );

    /* -------------------------
       VOICE CARD
    ------------------------- */

    $("voiceAnalysisStatus").textContent = "COMPLETED";

    $("voiceRiskScore").textContent =
      voiceScore + "%";

    $("voiceMeterFill").style.width =
      voiceScore + "%";

    const voiceFlags =
      window.currentVoiceFlags || localResult.flags || [];

    $("voiceUrgency").textContent =
      voiceFlags.some(f =>
        String(f.title || "").toLowerCase().includes("urgency")
      )
        ? "Detected"
        : "Low";

    $("voiceManipulation").textContent =
      voiceFlags.length >= 2
        ? "Detected"
        : "Low";

    $("voiceAlertLevel").textContent =
      voiceScore >= 65
        ? "HIGH"
        : voiceScore >= 35
        ? "MEDIUM"
        : "LOW";

    const backendVoiceScript =
      window.currentBackendVoiceScript ||
      report.voice_intervention?.voice_script ||
      "";

    latestVoiceScript =
      backendVoiceScript ||
      $("verdictText").textContent;

    $("voiceAnalysisText").textContent =
      latestVoiceScript || "Voice analysis completed.";


    /* -------------------------
       GEMINI CARD
    ------------------------- */

    $("geminiAnalysisStatus").textContent = "COMPLETED";

    $("geminiRiskScore").textContent =
      geminiScore + "%";

    $("geminiMeterFill").style.width =
      geminiScore + "%";

    $("geminiThreatType").textContent =
      report.threat_type || "Unknown";

    $("geminiConfidence").textContent =
      (report.confidence ?? 0) + "%";

    $("geminiVerdict").textContent =
      report.verdict || "UNKNOWN";

    $("geminiAnalysisText").textContent =
      report.recommended_action ||
      "Review the warning signs before taking action.";


    /* -------------------------
       FINAL OVERALL RESULT
    ------------------------- */

    renderResult(
      overallScore,
      report.red_flags?.length
        ? report.red_flags
        : localResult.flags
    );

    /* -------------------------
       ELEVENLABS AUDIO
    ------------------------- */

    if (data.audio_base64) {
      latestAudio = data.audio_base64;
    } else {
      latestAudio = null;
    }

    return data;

  } catch (error) {

    console.error("Backend analysis error:", error);

    const localResult = calculateRisk(text);

    window.ocrRiskScore = localResult.score;

    $("voiceAnalysisStatus").textContent =
      "LOCAL MODE";

    $("geminiAnalysisStatus").textContent =
      "UNAVAILABLE";

    $("voiceRiskScore").textContent =
      localResult.score + "%";

    $("voiceMeterFill").style.width =
      localResult.score + "%";

    $("voiceAnalysisText").textContent =
      "Backend AI analysis is temporarily unavailable. Local rule-based analysis is shown.";

    renderResult(
      localResult.score,
      localResult.flags
    );
  }
}


/* ================================
   MAIN ANALYZE BUTTON
================================ */

$("analyzeBtn").addEventListener("click", async () => {

  const text = $("threatText").value.trim();

  if (!text) {
    $("threatText").focus();
    $("threatText").placeholder =
      "Please paste a suspicious message first…";
    return;
  }

  /*
    Local score is stored BEFORE Gemini call.
    This becomes the separate Voice / Rule Risk.
  */
  const localResult = calculateRisk(text);

  window.ocrRiskScore = localResult.score;
  window.currentVoiceFlags = localResult.flags;
  window.currentBackendVoiceScript = "";

  renderResult(
    localResult.score,
    localResult.flags
  );

  await analyzeTextWithBackend(text);
});


/* ================================
   SAMPLE BUTTONS
================================ */

document.querySelectorAll("[data-sample]").forEach((btn) => {

  btn.addEventListener("click", () => {

    const sample = samples[btn.dataset.sample];

    if (!sample) return;

    $("threatText").value = sample;
    $("threatText").focus();
  });

});


/* ================================
   IMAGE UPLOAD
================================ */

$("imageInput").addEventListener("change", async (e) => {

  const file = e.target.files[0];

  if (!file) return;

  const url = URL.createObjectURL(file);

  $("imagePreview").src = url;
  $("imagePreview").classList.remove("hidden");

  window.selectedImageFile = file;

  try {

    $("resultStatus").textContent =
      "ANALYZING IMAGE...";

    $("resultStatus").className =
      "chip neutral";

    const formData = new FormData();

    formData.append("file", file);

    const response = await fetch(
      `${BACKEND_URL}/api/v1/analyze-threat`,
      {
        method: "POST",
        body: formData
      }
    );

    if (!response.ok) {
      throw new Error(
        "Image API HTTP " + response.status
      );
    }

    const data = await response.json();

    const threatIntel =
      data.threat_intelligence || {};

    const score = Number(
      data.risk_score ??
      threatIntel.risk_score ??
      0
    );

    /*
      IMPORTANT:
      Image rule/OCR score becomes Voice Risk.
    */
    window.ocrRiskScore = score;

    window.currentVoiceFlags =
      threatIntel.itemized_red_flags || [];

    window.currentBackendVoiceScript =
      data.voice_synthesis_alert?.script || "";

    /* OCR text */

    const ocrText =
      data.ocr_extracted_text || "";

    if (ocrText.trim()) {
      $("threatText").value = ocrText;
    }

    /* Voice card */

    $("voiceAnalysisCard").classList.remove("hidden");

    $("voiceAnalysisStatus").textContent =
      "COMPLETED";

    $("voiceRiskScore").textContent =
      score + "%";

    $("voiceMeterFill").style.width =
      score + "%";

    const imageFlags =
      threatIntel.itemized_red_flags || [];

    $("voiceUrgency").textContent =
      imageFlags.some(f =>
        String(f.title || "")
          .toLowerCase()
          .includes("urgency")
      )
        ? "Detected"
        : "Low";

    $("voiceManipulation").textContent =
      imageFlags.length >= 2
        ? "Detected"
        : "Low";

    $("voiceAlertLevel").textContent =
      score >= 65
        ? "HIGH"
        : score >= 35
        ? "MEDIUM"
        : "LOW";

    $("voiceAnalysisText").textContent =
      data.voice_synthesis_alert?.script ||
      "Voice analysis completed.";

    latestVoiceScript =
      data.voice_synthesis_alert?.script || "";

    /* Show initial image result */

    renderResult(
      score,
      imageFlags
    );

    /* Run Gemini using OCR text */

    if (ocrText.trim()) {
      await analyzeTextWithBackend(ocrText);
    }

  } catch (error) {

    console.error("Image analysis error:", error);

    $("resultStatus").textContent =
      "IMAGE ANALYSIS FAILED";

    $("resultStatus").className =
      "chip neutral";

    alert(
      "Image analysis failed. Please check that the backend is running."
    );
  }

});


/* ================================
   IMAGE VIEWER
================================ */

if ($("imagePreview")) {

  $("imagePreview").addEventListener("click", () => {

    if (!$("imagePreview").src) return;

    if ($("viewerImage")) {
      $("viewerImage").src =
        $("imagePreview").src;
    }

    if ($("imageViewer")) {
      $("imageViewer").classList.remove("hidden");
    }

  });

}


if ($("closeImageViewer")) {

  $("closeImageViewer").addEventListener("click", () => {

    $("imageViewer").classList.add("hidden");

  });

}


if ($("imageViewer")) {

  $("imageViewer").addEventListener("click", (e) => {

    if (e.target === $("imageViewer")) {
      $("imageViewer").classList.add("hidden");
    }

  });

}


/* ================================
   VOICE BUTTON
================================ */

$("voiceBtn").addEventListener("click", () => {

  /*
    Prefer ElevenLabs audio when available.
  */

  if (latestAudio) {

    try {

      const audio = new Audio(latestAudio);

      audio.play();

      return;

    } catch (error) {

      console.error(
        "ElevenLabs playback failed:",
        error
      );
    }
  }


  /*
    Browser speech fallback
  */

  if (!("speechSynthesis" in window)) {

    alert(
      "Voice synthesis is not supported in this browser."
    );

    return;
  }

  speechSynthesis.cancel();

  const script =
    latestVoiceScript ||
    $("verdictTitle").textContent +
    ". " +
    $("verdictText").textContent;

  const msg =
    new SpeechSynthesisUtterance(script);

  msg.rate = 0.95;

  speechSynthesis.speak(msg);

});


/* ================================
   COMPLAINT DRAFT
================================ */

$("complaintBtn").addEventListener("click", () => {

  const text =
    $("threatText").value.trim() ||
    "[No suspicious message provided]";

  const now = new Date().toLocaleString();

  // Current Overall Risk
  const overallRisk =
    parseInt(($("riskScore").textContent || "0").replace("%", ""), 10) || 0;

  // Risk-based reporting recommendation
  let reportingSection = "";

  if (overallRisk > 35) {
    reportingSection =
`RECOMMENDED REPORTING ACTION

Based on the ShieldPlus.AI analysis, the Overall Risk Score is ${overallRisk}%.

This incident is recommended for reporting as a suspected cyber-fraud / cyber-crime case.

Submit this complaint to:
Cyber Crime Helpline: 1930
National Cyber Crime Reporting Portal

If any money has already been transferred or financial fraud has occurred, report the incident as soon as possible through the appropriate official cyber-crime channel.`;
  } else {
    reportingSection =
`REPORTING INFORMATION

The Overall Risk Score is ${overallRisk}%.

The result indicates a comparatively lower level of detected risk. However, if you believe that you have been targeted, suffered financial loss, or shared sensitive information, consider reporting the incident through the appropriate official cyber-crime channel.`;
  }

  $("complaintBox").classList.remove("hidden");

  $("complaintBox").textContent =
`CYBER CRIME INCIDENT COMPLAINT

Subject: Complaint Regarding Suspected Cyber Fraud / Online Scam

Date & Time of Report:
${now}

Respected Sir/Madam,

I would like to report a suspicious communication that may be related to cyber fraud, phishing, social engineering, or another form of online scam.

1. INCIDENT SUMMARY

The following suspicious message was analyzed using ShieldPlus.AI. The analysis identified certain warning signs that may indicate an attempt to manipulate the recipient into making a payment, sharing sensitive information, opening a suspicious link, or taking another potentially unsafe action.

2. ORIGINAL SUSPICIOUS MESSAGE

${text}

3. SHIELDPLUS.AI RISK ASSESSMENT

Overall Risk Score: ${overallRisk}%

This assessment is intended to highlight potentially suspicious indicators and should be reviewed together with the original communication and available evidence.

4. POTENTIAL WARNING SIGNS

The incident may involve one or more of the following:
• Urgent or threatening language
• Requests for OTP, PIN, password or other sensitive information
• Suspicious links or verification requests
• Payment, UPI, QR or money-transfer requests
• Fake job, reward, refund or account-verification claims
• Attempts to create fear, urgency or financial pressure

5. EVIDENCE AVAILABLE

The following evidence should be preserved, where applicable:
• Screenshot of the suspicious message
• Sender / caller details
• Suspicious URL, UPI ID or QR-code information
• Transaction or payment reference details
• Date and time of communication
• Relevant emails, phone numbers or other digital records

6. REQUEST FOR ACTION

I respectfully request the concerned authorities to review this incident, examine the available digital evidence, and take appropriate action in accordance with applicable law.

${reportingSection}

7. IMPORTANT NOTICE

This complaint draft has been generated with assistance from ShieldPlus.AI. The complainant should carefully review the information, correct any inaccurate details, and provide additional evidence or facts before submitting the complaint through an official channel.

--- END OF COMPLAINT ---`;
});

/* ================================
   HERO MINI BARS
================================ */

function updateHeroBars(score) {

  if ($("heroUrgencyBar")) {
    $("heroUrgencyBar").style.width =
      Math.min(100, score + 5) + "%";
  }

  if ($("heroDomainBar")) {
    $("heroDomainBar").style.width =
      Math.min(100, score) + "%";
  }

  if ($("heroPaymentBar")) {
    $("heroPaymentBar").style.width =
      Math.min(100, score - 5) + "%";
  }

  if ($("heroUrgencyLabel")) {
    $("heroUrgencyLabel").textContent =
      score >= 65 ? "High" :
      score >= 35 ? "Medium" :
      "Low";
  }

  if ($("heroDomainLabel")) {
    $("heroDomainLabel").textContent =
      score >= 65 ? "Suspicious" :
      score >= 35 ? "Review" :
      "Normal";
  }

  if ($("heroPaymentLabel")) {
    $("heroPaymentLabel").textContent =
      score >= 65 ? "High" :
      score >= 35 ? "Medium" :
      "Low";
  }
}


/* Update hero whenever final result changes */

const originalRenderResult = renderResult;

renderResult = function(score, flags) {

  originalRenderResult(score, flags);

  updateHeroBars(score);
};


/* ================================
   SCROLL REVEAL
================================ */

const observer =
  new IntersectionObserver(
    (entries) => {

      entries.forEach((entry) => {

        if (entry.isIntersecting) {
          entry.target.classList.add("visible");
        }

      });

    },
    {
      threshold: 0.08
    }
  );


document
  .querySelectorAll(".reveal")
  .forEach((el) => observer.observe(el));