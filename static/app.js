/* ShieldScan UI. All dynamic text is inserted with textContent (never innerHTML). */
const $ = (s, r = document) => r.querySelector(s);
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(k));
  return e;
}
const fmtSize = b => b > 1048576 ? (b / 1048576).toFixed(1) + " MB" : b > 1024 ? (b / 1024).toFixed(1) + " KB" : b + " B";
const KIND = { text: "Email / text", image: "Image", audio: "Audio", video: "Video" };
const history = [];
let previewUrl = null;

/* ---- tabs ---- */
document.querySelectorAll("nav button").forEach(b => b.addEventListener("click", () => {
  document.querySelectorAll("nav button").forEach(x => x.setAttribute("aria-selected", x === b));
  document.querySelectorAll(".view").forEach(v => v.hidden = v.id !== "view-" + b.dataset.view);
}));

/* ---- scanning ---- */
async function scan(fd, label, sourceFile = null) {
  $("#empty").hidden = true; $("#report").hidden = true; $("#loading").hidden = false;
  $("#loadingMsg").textContent = "Analysing " + label + "...";
  try {
    const r = await fetch("/api/scan", { method: "POST", body: fd });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || "Scan failed");
    history.unshift(j); renderHistory(); renderReport(j, sourceFile);
  } catch (e) {
    $("#report").replaceChildren(el("div", { class: "card" }, el("h3", {}, "Could not scan"), el("p", { class: "muted" }, e.message)));
    $("#report").hidden = false;
  } finally { $("#loading").hidden = true; }
}
function scanFile(f) { const fd = new FormData(); fd.append("file", f); scan(fd, f.name, f); }

const drop = $("#drop"), fileIn = $("#file");
fileIn.addEventListener("change", () => fileIn.files[0] && scanFile(fileIn.files[0]));
drop.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileIn.click(); } });
["dragenter", "dragover"].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", e => e.dataTransfer.files[0] && scanFile(e.dataTransfer.files[0]));
$("#scanText").addEventListener("click", () => {
  const t = $("#paste").value.trim(); if (!t) return;
  const fd = new FormData(); fd.append("text", t); scan(fd, "pasted text");
});

function renderHistory() {
  $("#history").hidden = !history.length;
  $("#historyList").replaceChildren(...history.slice(0, 8).map(h => el("li", {},
    el("button", { onclick: () => renderReport(h) }, el("span", { class: "fn" }, h.filename), el("span", { class: "pill " + h.level }, h.score + " " + h.level)))));
}

function gauge(score, level) {
  const R = 44, C = 2 * Math.PI * R, col = { Low: "var(--low)", Medium: "var(--med)", High: "var(--high)" }[level];
  const ns = "http://www.w3.org/2000/svg", s = document.createElementNS(ns, "svg");
  s.setAttribute("width", 104); s.setAttribute("height", 104); s.setAttribute("viewBox", "0 0 104 104");
  const mk = (stroke, dash) => { const c = document.createElementNS(ns, "circle");
    for (const [k, v] of Object.entries({ cx: 52, cy: 52, r: R, fill: "none", "stroke-width": 9, stroke, "stroke-linecap": "round", "stroke-dasharray": dash })) c.setAttribute(k, v); return c; };
  s.append(mk("color-mix(in srgb, var(--ink) 12%, transparent)", `${C} ${C}`), mk(col, `${C * score / 100} ${C}`));
  return el("div", { class: "gauge", role: "img", "aria-label": `Risk score ${score} out of 100` }, s, el("div", { class: "num" }, String(score)));
}

const HEAD = {
  High: "High risk - do not open",
  Medium: "Suspicious - verify first",
  Low: "No strong warning signs",
};

function renderPreview(r, sourceFile) {
  const p = el("div", { class: "preview" }, el("h4", {}, "Uploaded content"));
  const d = r.details || {};

  // Detect media from both MIME type and filename. Some Windows/browser
  // combinations report an empty or generic MIME type for uploaded files.
  const name = sourceFile ? String(sourceFile.name || "").toLowerCase() : "";
  const mime = sourceFile ? String(sourceFile.type || "").toLowerCase() : "";
  const isImage = mime.startsWith("image/") || /\.(jpg|jpeg|png|gif|webp|bmp|svg|avif|jfif)$/i.test(name);
  const isAudio = mime.startsWith("audio/") || /\.(mp3|wav|ogg|oga|m4a|aac|flac)$/i.test(name);
  const isVideo = mime.startsWith("video/") || /\.(mp4|webm|mov|avi|mkv|m4v|mpeg|mpg)$/i.test(name);
  const isText = mime.startsWith("text/") || /\.(txt|csv|log|json|xml|html|htm|eml)$/i.test(name);

  // For files selected in the browser, preview the original bytes locally.
  if (sourceFile) {
    if (isImage) {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      previewUrl = URL.createObjectURL(sourceFile);
      const img = el("img", { class: "media-preview", src: previewUrl, alt: "Uploaded image preview" });
      p.append(img, el("p", { class: "muted preview-caption" }, sourceFile.name));
      return p;
    }
    if (isAudio) {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      previewUrl = URL.createObjectURL(sourceFile);
      p.append(el("audio", { class: "media-player", controls: true, src: previewUrl }), el("p", { class: "muted preview-caption" }, sourceFile.name));
      return p;
    }
    if (isVideo) {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      previewUrl = URL.createObjectURL(sourceFile);
      p.append(el("video", { class: "media-preview video-preview", controls: true, preload: "metadata", src: previewUrl }), el("p", { class: "muted preview-caption" }, sourceFile.name));
      return p;
    }
    if (isText) {
      // Plain text can be shown directly; HTML/email is shown as text here unless the backend supplied a safe email preview.
      if (!d.preview) {
        const pre = el("pre", { class: "text-preview" }, "Loading uploaded text...");
        p.append(pre);
        sourceFile.text().then(t => { pre.textContent = t.slice(0, 20000); });
        return p;
      }
    }
  }

  // Safe server-side preview for .eml files: plain body + extracted inline images.
  if (d.preview) {
    if (d.preview.subject) p.append(el("div", { class: "preview-subject" }, el("strong", {}, "Subject: "), d.preview.subject));
    if (d.preview.body) p.append(el("pre", { class: "text-preview email-preview" }, d.preview.body));
    if (Array.isArray(d.preview.images) && d.preview.images.length) {
      const gallery = el("div", { class: "preview-gallery" });
      d.preview.images.forEach(im => gallery.append(
        el("figure", { class: "preview-figure" },
          el("img", { class: "media-preview", src: im.data_url, alt: im.filename || "Email image" }),
          el("figcaption", { class: "muted" }, im.filename || "Embedded image"))));
      p.append(gallery);
    }
    if (d.preview.body || (d.preview.images && d.preview.images.length)) return p;
  }

  p.append(el("p", { class: "muted" }, "A visual preview is not available for this file type. The original file was analysed without modification."));
  return p;
}

function renderReport(r, sourceFile = null) {
  const ev = r.evidence.length ? r.evidence.map(e => el("li", {}, el("span", { class: "dot " + e.severity }), el("span", {}, e.text)))
    : [el("li", {}, el("span", { class: "dot info" }), el("span", {}, "No suspicious indicators were found."))];
  const d = r.details || {}, rows = [["Type", KIND[r.kind]], ["Size", fmtSize(r.size_bytes)], ["Analysis time", r.elapsed_s + " s"]];
  if (d.duration_s) rows.push(["Duration", d.duration_s + " s"]);
  if (d.resolution) rows.push(["Resolution", d.resolution]);
  if (d.width) rows.push(["Dimensions", d.width + " x " + d.height]);
  if (d.urls_found != null) rows.push(["Links found", String(d.urls_found)]);
  if (r.ai_generated_likelihood != null) rows.push(["AI-written style", Math.round(r.ai_generated_likelihood * 100) + "%"]);
  const node = el("div", { class: "report" },
    el("div", { class: "rhead " + r.level }, gauge(r.score, r.level),
      el("div", {}, el("h2", {}, HEAD[r.level]), el("div", { class: "meta" }, r.filename + " - scanned " + r.scanned_at))),
    el("div", { class: "rbody" },
      renderPreview(r, sourceFile),
      el("div", { class: "sec" }, el("h4", {}, "What we found"), el("ul", { class: "ev" }, ev)),
      el("div", { class: "sec" }, el("h4", {}, "What to do"), el("ul", { class: "recs" }, r.recommendations.map(x => el("li", {}, x)))),
      el("div", { class: "sec" }, el("h4", {}, "Details"), el("dl", { class: "kv" }, rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]))),
      el("div", { class: "sec" }, el("h4", {}, "Detection models"), el("div", { class: "chips" }, r.models.map(m => el("span", {}, m)))),
      el("div", { class: "sec" }, el("h4", {}, "Checks performed"), el("ol", { class: "steps" }, r.steps.map(s => el("li", {}, s)))),
      el("div", { class: "sec" }, el("h4", {}, "File integrity"),
        el("p", { class: r.integrity.unchanged ? "ok" : "bad" }, r.integrity.unchanged ? "File unchanged by the scan (SHA-256 matches before and after)." : "WARNING: file hash changed during scan."),
        el("dl", { class: "kv" }, el("dt", {}, "SHA-256"), el("dd", {}, r.integrity.sha256_before))),
      el("div", { class: "actions" }, el("a", { href: "/api/report/" + r.id }, el("button", { class: "ghost", type: "button" }, "Download report (JSON)")))));
  $("#report").replaceChildren(node); $("#report").hidden = false; $("#empty").hidden = true;
}

window.ShieldUI = { el, $, fmtSize };
