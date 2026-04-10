const qs = (sel) => document.querySelector(sel);

function initParticles() {
  const canvas = qs("#particleCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  let w = 0;
  let h = 0;
  let raf = null;

  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (prefersReducedMotion) return;

  const particles = [];
  const maxParticles = 46;

  function resize() {
    w = window.innerWidth;
    h = window.innerHeight;
    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function spawn() {
    particles.length = 0;
    for (let i = 0; i < maxParticles; i++) {
      particles.push({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.16,
        vy: (Math.random() - 0.5) * 0.16,
        r: 0.8 + Math.random() * 1.8,
        a: 0.08 + Math.random() * 0.18,
      });
    }
  }

  function themeColor(alpha) {
    const theme = document.documentElement.getAttribute("data-theme") || "dark";
    return theme === "light" ? `rgba(70, 85, 130, ${alpha})` : `rgba(180, 220, 255, ${alpha})`;
  }

  function tick() {
    ctx.clearRect(0, 0, w, h);
    const c1 = themeColor(0.28);
    const c2 = themeColor(0.12);

    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < -10) p.x = w + 10;
      if (p.x > w + 10) p.x = -10;
      if (p.y < -10) p.y = h + 10;
      if (p.y > h + 10) p.y = -10;

      ctx.beginPath();
      ctx.fillStyle = themeColor(p.a);
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();
    }

    // Subtle nearby links
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i];
        const b = particles[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          const alpha = (1 - dist / 120) * 0.14;
          ctx.strokeStyle = alpha > 0.08 ? c1 : c2;
          ctx.globalAlpha = alpha;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
          ctx.globalAlpha = 1;
        }
      }
    }

    raf = requestAnimationFrame(tick);
  }

  resize();
  spawn();
  tick();

  window.addEventListener("resize", () => {
    resize();
    spawn();
  });
  const obs = new MutationObserver(() => {});
  obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
}

function initMicroInteractions() {
  const cards = Array.from(document.querySelectorAll(".card"));
  cards.forEach((card) => {
    card.addEventListener("mousemove", (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const rx = ((y / rect.height) - 0.5) * -4.5;
      const ry = ((x / rect.width) - 0.5) * 4.5;
      card.style.transform = `perspective(900px) rotateX(${rx.toFixed(2)}deg) rotateY(${ry.toFixed(2)}deg) translateY(-1px)`;
      card.style.setProperty("--mx", `${(x / rect.width) * 100}%`);
      card.style.setProperty("--my", `${(y / rect.height) * 100}%`);
    });
    card.addEventListener("mouseleave", () => {
      card.style.transform = "";
      card.style.setProperty("--mx", "50%");
      card.style.setProperty("--my", "50%");
    });
  });

  const btns = Array.from(document.querySelectorAll(".btn"));
  btns.forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const rect = btn.getBoundingClientRect();
      const r = document.createElement("span");
      r.className = "btn-ripple";
      r.style.left = `${e.clientX - rect.left}px`;
      r.style.top = `${e.clientY - rect.top}px`;
      btn.appendChild(r);
      setTimeout(() => r.remove(), 560);
    });
  });
}

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("theme", theme);
  const label = qs("#themeLabel");
  if (label) label.textContent = theme === "light" ? "Light" : "Dark";
}

function initTheme() {
  const saved = localStorage.getItem("theme");
  setTheme(saved || "dark");
  const btn = qs("#themeToggle");
  if (btn) {
    btn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      setTheme(current === "dark" ? "light" : "dark");
    });
  }
}

function badgeClassFor(prediction, risk) {
  if (prediction === "phishing" || risk === "high") return "bad";
  if (risk === "medium") return "warn";
  return "good";
}

function setScanning(on, opts = {}) {
  const s = qs("#scanStatus");
  const b = qs("#scanBtn");
  if (s) s.classList.toggle("on", !!on);
  if (b && opts.disableButton !== false) b.disabled = !!on;
}

function escapeHtml(s) {
  return (s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function statusClass(status) {
  if (!status) return "warn";
  const s = String(status).toLowerCase();
  if (s.includes("malicious") || s === "bad") return "bad";
  if (s.includes("suspicious")) return "warn";
  if (s.includes("clean") || s.includes("ok") || s.includes("safe")) return "good";
  if (s.includes("unavailable")) return "warn";
  return "warn";
}

function flattenIntelProviders(threatIntel) {
  const ti = threatIntel || {};
  if (Array.isArray(ti.providers)) return ti.providers;
  // URL scans may include nested { url: {providers}, domain: {providers} }
  const out = [];
  if (ti.url && Array.isArray(ti.url.providers)) {
    ti.url.providers.forEach((p) => out.push({ ...p, scope: "url" }));
  }
  if (ti.domain && Array.isArray(ti.domain.providers)) {
    ti.domain.providers.forEach((p) => out.push({ ...p, scope: "domain" }));
  }
  return out;
}

async function postJSON(url, body, opts = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: opts.signal,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.error || `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return data;
}

async function getJSON(url) {
  const res = await fetch(url);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.error || `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return data;
}

function renderScanResult(r) {
  const predBadge = qs("#predBadge");
  const riskBadge = qs("#riskBadge");
  const confBadge = qs("#confBadge");
  const threatVal = qs("#threatVal");
  const threatBar = qs("#threatBar");
  const intelBody = qs("#intelBody");
  const intelDetailsBody = qs("#intelDetailsBody");
  const intelSummaryMini = qs("#intelSummaryMini");
  const reasonsList = qs("#reasonsList");
  const highlightsBox = qs("#highlightsBox");
  const scoreBreakdownList = qs("#scoreBreakdownList");
  const scoreBreakdownMeta = qs("#scoreBreakdownMeta");
  const scoreStack = qs("#scoreStack");
  const scoreStackLegend = qs("#scoreStackLegend");

  const cls = badgeClassFor(r.prediction, r.risk_level);
  if (predBadge) {
    predBadge.className = `badge ${cls}`;
    predBadge.textContent = r.prediction?.toUpperCase() || "—";
  }
  if (riskBadge) riskBadge.textContent = `Risk: ${(r.risk_level || "—").toUpperCase()}`;
  if (confBadge) confBadge.textContent = `Conf: ${Math.round((r.confidence || 0) * 100)}%`;

  const score = Math.max(0, Math.min(100, r.threat_score || 0));
  if (threatVal) threatVal.textContent = `${score}`;
  if (threatBar) {
    threatBar.style.width = `${score}%`;
    threatBar.className = `bar-fill ${cls}`;
  }

  if (intelBody) {
    const ti = r.threat_intel || {};
    intelBody.innerHTML = `<div><b>${escapeHtml(ti.status || "unknown")}</b> — ${escapeHtml(
      ti.summary || ""
    )}</div>`;
  }

  if (intelDetailsBody) {
    const ti = r.threat_intel || {};
    const providers = flattenIntelProviders(ti);
    if (!providers.length) {
      intelDetailsBody.textContent = "No provider details (keys not configured or no data).";
      if (intelSummaryMini) intelSummaryMini.textContent = "—";
    } else {
      const counts = { malicious: 0, suspicious: 0, clean: 0, error: 0, unavailable: 0, unknown: 0 };
      providers.forEach((p) => {
        const st = String(p.status || "unknown").toLowerCase();
        if (counts[st] !== undefined) counts[st] += 1;
        else counts.unknown += 1;
      });
      if (intelSummaryMini) {
        intelSummaryMini.textContent = `${counts.malicious} malicious • ${counts.suspicious} suspicious • ${counts.clean} clean`;
      }

      intelDetailsBody.innerHTML = providers
        .map((p) => {
          const st = String(p.status || "unknown");
          const stCls = statusClass(st);
          const scope = p.scope ? `<span class="kv">scope: ${escapeHtml(p.scope)}</span>` : "";
          const delta = Number.isFinite(p.score_delta) ? `<span class="kv">score Δ ${p.score_delta}</span>` : "";

          // Show some compact VT/GSB specifics if present
          let extra = "";
          const det = p.details || {};
          if (det.last_analysis_stats) {
            const s = det.last_analysis_stats;
            extra = `<span class="kv">VT m:${s.malicious || 0} s:${s.suspicious || 0} h:${s.harmless || 0}</span>`;
          } else if (Array.isArray(det.matches) && det.matches.length) {
            const types = [...new Set(det.matches.map((m) => m.threatType).filter(Boolean))].slice(0, 4);
            extra = `<span class="kv">GSB: ${escapeHtml(types.join(", ") || "match")}</span>`;
          }

          return `<div class="intel-provider">
            <div class="intel-top">
              <div class="intel-name">${escapeHtml(p.provider || "provider")}</div>
              <div class="intel-status ${stCls}">${escapeHtml(st.toUpperCase())}</div>
            </div>
            <div class="mini">${escapeHtml(p.summary || "")}</div>
            <div class="intel-kv">${scope}${delta}${extra}</div>
          </div>`;
        })
        .join("");
    }
  }

  if (reasonsList) {
    const reasons = Array.isArray(r.reasons) ? r.reasons : [];
    reasonsList.innerHTML = reasons
      .slice(0, 10)
      .map((x) => `<li><b>${escapeHtml(x.title || "Reason")}</b><div class="mini">${escapeHtml(x.detail || "")}</div></li>`)
      .join("");
  }

  if (highlightsBox) {
    const h = Array.isArray(r.highlights) ? r.highlights : [];
    if (!h.length) {
      highlightsBox.textContent = "—";
    } else {
      highlightsBox.innerHTML = h
        .slice(0, 16)
        .map(
          (x) =>
            `<span class="chip" title="${escapeHtml(x.snippet || "")}"><span class="icon"></span>${escapeHtml(
              x.term || ""
            )}</span>`
        )
        .join("");
    }
  }

  if (scoreBreakdownList) {
    const sb = r.score_breakdown || r.meta?.score_breakdown || null;
    if (!sb) {
      scoreBreakdownList.innerHTML = `<div class="mini">No breakdown data.</div>`;
      if (scoreBreakdownMeta) scoreBreakdownMeta.textContent = "—";
      if (scoreStack) scoreStack.innerHTML = "";
      if (scoreStackLegend) scoreStackLegend.textContent = "—";
    } else {
      const rows = [
        { key: "base", name: "Baseline", value: Number(sb.base || 0), cls: "base" },
        { key: "rules", name: "Rules / Feature heuristics", value: Number(sb.rules || 0), cls: "rules" },
        { key: "intel", name: "Threat intel", value: Number(sb.intel || 0), cls: "intel" },
        { key: "ml", name: "AI model signal", value: Number(sb.ml || 0), cls: "ml", absolute: true },
      ];

      if (scoreBreakdownMeta) {
        const hw = Number(sb.blend?.heuristic_weight ?? 0.28);
        const mw = Number(sb.blend?.ml_weight ?? 0.72);
        scoreBreakdownMeta.textContent = sb.ml != null ? `Blend: ML ${Math.round(mw * 100)}% / Heuristic ${Math.round(hw * 100)}%` : "Heuristic-only";
      }

      scoreBreakdownList.innerHTML = rows
        .map((row) => {
          const v = Number.isFinite(row.value) ? row.value : 0;
          const w = Math.max(0, Math.min(100, row.absolute ? Math.abs(v) : Math.abs(v)));
          const signed = v > 0 ? `+${Math.round(v)}` : `${Math.round(v)}`;
          return `<div class="srow">
            <div class="srow-top">
              <div class="srow-name">${escapeHtml(row.name)}</div>
              <div class="srow-val">${escapeHtml(signed)}</div>
            </div>
            <div class="sbar"><div class="sbar-fill ${row.cls}" style="width:${w}%"></div></div>
          </div>`;
        })
        .join("");

      // Stacked composition bar with center axis:
      // positive weighted contributions extend right, negatives extend left.
      if (scoreStack) {
        const mlW = Number(sb.blend?.ml_weight ?? (sb.ml != null ? 0.72 : 0));
        const heurW = Number(sb.blend?.heuristic_weight ?? (sb.ml != null ? 0.28 : 1.0));
        const weighted = [
          { name: "base", cls: "base", value: Number(sb.base || 0) * heurW },
          { name: "rules", cls: "rules", value: Number(sb.rules || 0) * heurW },
          { name: "intel", cls: "intel", value: Number(sb.intel || 0) * heurW },
          { name: "ml", cls: "ml", value: Number(sb.ml || 0) * mlW },
        ];

        const positives = weighted.filter((x) => x.value > 0);
        const negatives = weighted.filter((x) => x.value < 0);
        const posTotal = positives.reduce((a, b) => a + b.value, 0);
        const negTotal = Math.abs(negatives.reduce((a, b) => a + b.value, 0));
        const scale = Math.max(1, posTotal + negTotal);

        let rightCursor = 50;
        let leftCursor = 50;
        const segs = [];

        positives.forEach((x) => {
          const wPct = (x.value / scale) * 100;
          segs.push(
            `<div class="seg pos ${x.cls}" title="${x.name}: +${x.value.toFixed(1)}" style="left:${rightCursor.toFixed(
              3
            )}%;width:${wPct.toFixed(3)}%"></div>`
          );
          rightCursor += wPct;
        });

        negatives.forEach((x) => {
          const abs = Math.abs(x.value);
          const wPct = (abs / scale) * 100;
          leftCursor -= wPct;
          segs.push(
            `<div class="seg neg" title="${x.name}: ${x.value.toFixed(1)}" style="left:${leftCursor.toFixed(
              3
            )}%;width:${wPct.toFixed(3)}%"></div>`
          );
        });

        scoreStack.innerHTML = segs.join("");
        if (scoreStackLegend) {
          const finalV = Number(sb.final || r.threat_score || 0);
          scoreStackLegend.textContent = `Weighted contributions sum to final score ≈ ${Math.round(finalV)} (right = increases risk, left = decreases risk).`;
        }
      }
    }
  }
}

function initScanPage() {
  const scanBtn = qs("#scanBtn");
  if (!scanBtn) return;

  let lastScanId = null;
  let lastScanResult = null;
  let liveController = null;
  let liveDebounceT = null;
  let lastLiveKey = "";
  const exportJsonBtn = qs("#exportJsonBtn");
  const exportPdfBtn = qs("#exportPdfBtn");
  const scanInputEl = qs("#scanInput");
  const inputTypeEl = qs("#inputType");
  const heavyModeEl = qs("#heavyMode");
  const chatLog = qs("#chatLog");
  const chatInput = qs("#chatInput");
  const chatSendBtn = qs("#chatSendBtn");
  const chatClearBtn = qs("#chatClearBtn");

  function addMsg(role, text) {
    if (!chatLog) return;
    const el = document.createElement("div");
    el.className = `msg ${role}`;
    const head = document.createElement("div");
    head.className = "msg-head";
    head.innerHTML = `<span>${role === "user" ? "You" : "Assistant"}</span><span class="mini">${new Date()
      .toISOString()
      .slice(11, 19)}</span>`;
    const body = document.createElement("div");
    body.className = "msg-body";
    body.textContent = text || "";
    el.appendChild(head);
    el.appendChild(body);
    chatLog.appendChild(el);
    chatLog.scrollTop = chatLog.scrollHeight;
  }

  async function sendChat() {
    if (!chatInput || !chatSendBtn) return;
    const msg = (chatInput.value || "").trim();
    if (!msg) return;
    if (!lastScanId && !lastScanResult) {
      addMsg("assistant", "Run a scan first so I can explain the result.");
      return;
    }
    addMsg("user", msg);
    chatInput.value = "";
    chatSendBtn.disabled = true;
    try {
      const res = await postJSON("/api/chat", {
        message: msg,
        scan_id: lastScanId,
        scan_result: lastScanResult,
      });
      addMsg("assistant", res.reply || "No reply.");
    } catch (e) {
      addMsg("assistant", e.message || "Chat failed");
    } finally {
      chatSendBtn.disabled = false;
    }
  }

  function setExportEnabled(on) {
    if (exportJsonBtn) exportJsonBtn.disabled = !on;
    if (exportPdfBtn) exportPdfBtn.disabled = !on;
  }

  function setHealth(text) {
    const health = qs("#healthPill");
    if (health) health.textContent = text;
  }

  function scheduleLiveScan() {
    if (!scanInputEl) return;
    const input = (scanInputEl.value || "").trim();
    const inputType = inputTypeEl?.value || "auto";
    const heavy = (heavyModeEl?.value || "0") === "1";

    // Live scan uses fast mode only (avoid heavy async loops while typing)
    if (heavy) return;

    // Avoid scanning tiny inputs
    if (input.length < 6) {
      lastLiveKey = "";
      return;
    }

    const key = `${inputType}:${input}`;
    if (key === lastLiveKey) return;
    lastLiveKey = key;

    clearTimeout(liveDebounceT);
    liveDebounceT = setTimeout(async () => {
      // Cancel previous live request
      if (liveController) liveController.abort();
      liveController = new AbortController();

      setHealth("Auto-scanning");
      setScanning(true, { disableButton: false });
      try {
        const res = await postJSON(
          "/api/scan",
          { input, input_type: inputType, heavy: false },
          { signal: liveController.signal }
        );
        // Live scans don't overwrite lastScanId (history would fill fast), but we keep lastScanResult for chat.
        lastScanResult = res;
        renderScanResult(res);
      } catch (e) {
        if (e?.name === "AbortError") return;
        // keep quiet during typing; only surface state
        setHealth("Ready");
      } finally {
        setScanning(false, { disableButton: false });
        setHealth("Ready");
      }
    }, 450);
  }

  setExportEnabled(false);

  scanBtn.addEventListener("click", async () => {
    const input = (qs("#scanInput")?.value || "").trim();
    const inputType = qs("#inputType")?.value || "auto";
    const heavy = (qs("#heavyMode")?.value || "0") === "1";
    if (!input) return;

    // Cancel live scan request if user manually triggers scan
    if (liveController) liveController.abort();

    setScanning(true, { disableButton: true });
    setExportEnabled(false);

    try {
      const res = await postJSON("/api/scan", { input, input_type: inputType, heavy });
      if (res.async && res.job_id) {
        const jobId = res.job_id;
        const params = new URLSearchParams({ input, input_type: inputType });
        let attempts = 0;
        while (attempts++ < 40) {
          await new Promise((r) => setTimeout(r, 250));
          const jr = await getJSON(`/api/job/${jobId}?${params.toString()}`);
          if (jr.status && jr.status !== "done") continue;
          lastScanId = jr.scan_id;
          lastScanResult = jr;
          renderScanResult(jr);
          setExportEnabled(true);
          addMsg("assistant", "Scan complete. Ask me why this was flagged, or what to do next.");
          break;
        }
      } else {
        lastScanId = res.scan_id;
        lastScanResult = res;
        renderScanResult(res);
        setExportEnabled(true);
        addMsg("assistant", "Scan complete. Ask me why this was flagged, or what to do next.");
      }
    } catch (e) {
      const health = qs("#healthPill");
      if (health) health.textContent = "Error";
      alert(e.message || "Scan failed");
    } finally {
      setScanning(false, { disableButton: true });
      const health = qs("#healthPill");
      if (health) health.textContent = "Ready";
    }
  });

  if (exportJsonBtn) {
    exportJsonBtn.addEventListener("click", () => {
      if (!lastScanId) return;
      window.open(`/api/export/${lastScanId}?format=json`, "_blank");
    });
  }
  if (exportPdfBtn) {
    exportPdfBtn.addEventListener("click", () => {
      if (!lastScanId) return;
      window.open(`/api/export/${lastScanId}?format=pdf`, "_blank");
    });
  }

  if (chatSendBtn) chatSendBtn.addEventListener("click", () => sendChat());
  if (chatInput) {
    chatInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        sendChat();
      }
    });
  }
  if (chatClearBtn && chatLog) {
    chatClearBtn.addEventListener("click", () => {
      chatLog.innerHTML = "";
      addMsg("assistant", "Cleared. Run a scan, then ask a question.");
    });
  }

  // Initial greeting
  addMsg("assistant", "Paste a URL/domain/email, run Scan Now, then ask me to explain the result in plain English.");

  // Live scanning (debounced) as user types
  if (scanInputEl) scanInputEl.addEventListener("input", scheduleLiveScan);
  if (inputTypeEl) inputTypeEl.addEventListener("change", scheduleLiveScan);
}

function initHistoryPage() {
  const tbody = qs("#historyTbody");
  if (!tbody) return;

  const q = qs("#histQuery");
  const risk = qs("#histRisk");
  const pred = qs("#histPred");
  const refresh = qs("#refreshHistoryBtn");

  async function load() {
    const params = new URLSearchParams();
    if (q?.value) params.set("query", q.value.trim());
    if (risk?.value) params.set("risk", risk.value);
    if (pred?.value) params.set("prediction", pred.value);
    params.set("limit", "50");
    const res = await getJSON(`/api/history?${params.toString()}`);
    const items = res.items || [];
    tbody.innerHTML = items
      .map((x) => {
        const cls = badgeClassFor(x.prediction, x.risk_level);
        return `<tr>
          <td>${x.id}</td>
          <td class="mini">${escapeHtml(x.created_at || "")}</td>
          <td>${escapeHtml(x.input_type || "")}</td>
          <td title="${escapeHtml(x.raw_input || "")}">${escapeHtml((x.raw_input || "").slice(0, 56))}</td>
          <td><span class="badge ${cls}" style="padding:6px 10px;border-radius:12px;">${escapeHtml(
            (x.prediction || "").toUpperCase()
          )}</span></td>
          <td>${x.threat_score}</td>
          <td>
            <div class="actions-inline">
              <button class="btn" data-export-json="${x.id}" type="button">JSON</button>
              <button class="btn" data-export-pdf="${x.id}" type="button">PDF</button>
            </div>
          </td>
        </tr>`;
      })
      .join("");

    tbody.querySelectorAll("button[data-export-json]").forEach((b) => {
      b.addEventListener("click", () => window.open(`/api/export/${b.dataset.exportJson}?format=json`, "_blank"));
    });
    tbody.querySelectorAll("button[data-export-pdf]").forEach((b) => {
      b.addEventListener("click", () => window.open(`/api/export/${b.dataset.exportPdf}?format=pdf`, "_blank"));
    });
  }

  const debounced = (() => {
    let t = null;
    return () => {
      clearTimeout(t);
      t = setTimeout(() => load().catch(() => {}), 220);
    };
  })();

  [q, risk, pred].forEach((el) => el && el.addEventListener("input", debounced));
  if (refresh) refresh.addEventListener("click", () => load().catch(() => {}));

  load().catch(() => {});
}

function initAnalyticsPage() {
  const dist = qs("#distChart");
  const trend = qs("#trendChart");
  if (!dist || !trend || typeof Chart === "undefined") return;

  let distChart = null;
  let trendChart = null;

  function chartColors() {
    const theme = document.documentElement.getAttribute("data-theme") || "dark";
    const grid = theme === "light" ? "rgba(12,18,40,0.08)" : "rgba(255,255,255,0.10)";
    const text = theme === "light" ? "rgba(12,18,40,0.75)" : "rgba(255,255,255,0.75)";
    return { grid, text };
  }

  async function load() {
    const res = await getJSON("/api/history?limit=120");
    const items = res.items || [];

    const safe = items.filter((x) => x.prediction === "safe").length;
    const phish = items.filter((x) => x.prediction === "phishing").length;

    const { grid, text } = chartColors();

    const labels = items
      .slice()
      .reverse()
      .slice(-30)
      .map((x) => (x.created_at || "").slice(11, 19));
    const scores = items
      .slice()
      .reverse()
      .slice(-30)
      .map((x) => x.threat_score || 0);

    if (distChart) distChart.destroy();
    distChart = new Chart(dist, {
      type: "doughnut",
      data: {
        labels: ["Safe", "Phishing"],
        datasets: [
          {
            data: [safe, phish],
            backgroundColor: ["rgba(34,197,94,0.85)", "rgba(239,68,68,0.85)"],
            borderColor: "rgba(255,255,255,0.10)",
          },
        ],
      },
      options: {
        plugins: { legend: { labels: { color: text } } },
      },
    });

    if (trendChart) trendChart.destroy();
    trendChart = new Chart(trend, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Threat score",
            data: scores,
            borderColor: "rgba(34,211,238,0.9)",
            backgroundColor: "rgba(124,58,237,0.15)",
            tension: 0.35,
            fill: true,
          },
        ],
      },
      options: {
        scales: {
          x: { grid: { color: grid }, ticks: { color: text } },
          y: { grid: { color: grid }, ticks: { color: text }, suggestedMin: 0, suggestedMax: 100 },
        },
        plugins: { legend: { labels: { color: text } } },
      },
    });

    const recent = qs("#recentScans");
    if (recent) {
      recent.innerHTML = items.slice(0, 10).map((x) => {
        const cls = badgeClassFor(x.prediction, x.risk_level);
        return `<div class="mini-item">
          <div class="mini-left">
            <div><b>#${x.id}</b> <span class="mini">${escapeHtml(x.created_at || "")}</span></div>
            <div class="mini">${escapeHtml((x.raw_input || "").slice(0, 72))}</div>
          </div>
          <div class="mini-right">
            <div><span class="badge ${cls}" style="padding:6px 10px;border-radius:12px;">${escapeHtml((x.prediction || "").toUpperCase())}</span></div>
            <div class="mini">Threat ${x.threat_score}</div>
          </div>
        </div>`;
      }).join("");
    }
  }

  const refresh = qs("#refreshAnalyticsBtn");
  if (refresh) refresh.addEventListener("click", () => load().catch(() => {}));

  // Reload charts when theme changes
  const obs = new MutationObserver(() => load().catch(() => {}));
  obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

  load().catch(() => {});
}

document.addEventListener("DOMContentLoaded", () => {
  initParticles();
  initMicroInteractions();
  initTheme();
  initScanPage();
  initHistoryPage();
  initAnalyticsPage();
});

