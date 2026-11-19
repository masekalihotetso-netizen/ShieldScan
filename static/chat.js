/* End-to-end encrypted chat. Keys are generated in the browser and never leave it.
   ECDH P-256 -> AES-256-GCM. The server only relays public keys and ciphertext.
   Everything received is decrypted locally and scanned before it can be opened. */
(() => {
  const { el, $, fmtSize } = window.ShieldUI;
  const enc = new TextEncoder(), dec = new TextDecoder();
  let st = null;   // {room,name,keys,pubJwk,aes,peer,after,timer}
  const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
  const b64 = buf => { let s = ""; const u = new Uint8Array(buf); for (let i = 0; i < u.length; i += 32768) s += String.fromCharCode(...u.subarray(i, i + 32768)); return btoa(s); };
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  async function post(url, body) {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json(); if (!r.ok) throw new Error(j.error || "Request failed"); return j;
  }

  $("#joinBtn").addEventListener("click", async () => {
    const room = $("#room").value.trim(), name = $("#name").value.trim(), err = $("#joinErr"); err.textContent = "";
    if (!room || !name) { err.textContent = "Enter a room code and your name."; return; }
    if (!window.crypto?.subtle) { err.textContent = "This browser blocks encryption here. Use http://127.0.0.1:5000 or HTTPS."; return; }
    try {
      const keys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
      const pubJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
      await post("/api/chat/join", { room, name, pub: pubJwk });
      st = { room, name, keys, pubJwk, aes: null, peer: null, after: 0, seen: new Set() };
      $("#join").hidden = true; $("#chat").hidden = false; $("#roomLabel").textContent = "Room: " + room;
      poll(); st.timer = setInterval(poll, 1500);
    } catch (e) { err.textContent = e.message; }
  });

  async function deriveIfReady(users) {
    if (st.aes) return;
    const peer = Object.keys(users).find(n => n !== st.name);
    if (!peer) return;
    const peerKey = await crypto.subtle.importKey("jwk", users[peer], { name: "ECDH", namedCurve: "P-256" }, false, []);
    st.aes = await crypto.subtle.deriveKey({ name: "ECDH", public: peerKey }, st.keys.privateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    st.peer = peer;
    const fp = [JSON.stringify(st.pubJwk.x + st.pubJwk.y), JSON.stringify(users[peer].x + users[peer].y)].sort().join("|");
    const h = hex(await crypto.subtle.digest("SHA-256", enc.encode(fp))).slice(0, 20).match(/.{1,5}/g).join(" ");
    $("#peerLabel").textContent = "connected with " + peer;
    $("#safety").textContent = "Safety number " + h;
  }

  async function encrypt(obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, st.aes, enc.encode(JSON.stringify(obj)));
    return { iv: b64(iv), ct: b64(ct) };
  }
  async function decrypt(m) {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(m.iv) }, st.aes, unb64(m.ct));
    return JSON.parse(dec.decode(pt));
  }

  async function poll() {
    try {
      const r = await (await fetch(`/api/chat/poll?room=${encodeURIComponent(st.room)}&after=${st.after}`)).json();
      await deriveIfReady(r.users);
      for (const m of r.msgs) {
        st.after = Math.max(st.after, m.id);
        if (st.seen.has(m.id) || !st.aes) continue; st.seen.add(m.id);
        try { await show(m.from, await decrypt(m), m.from === st.name); }
        catch { addMsg(m.from, el("em", {}, "Could not decrypt this message (tampered or wrong key)."), false); }
      }
    } catch { /* transient network error: retry next tick */ }
  }

  function addMsg(who, body, me) {
    const box = $("#msgs"), node = el("div", { class: "msg" + (me ? " me" : "") }, el("div", { class: "who" }, me ? "You" : who), body);
    box.append(node); box.scrollTop = box.scrollHeight; return node;
  }

  function warnBox(rep) {
    const items = rep.evidence.filter(e => e.severity !== "info").slice(0, 3);
    return el("div", { class: "warn " + rep.level },
      el("strong", {}, `Scan: ${rep.score}/100 - ${rep.level} risk`),
      items.length ? el("ul", {}, items.map(i => el("li", {}, i.text))) : null);
  }

  async function scanBlob(blob, name) {
    const fd = new FormData(); fd.append("file", blob, name);
    const r = await fetch("/api/scan", { method: "POST", body: fd }), j = await r.json();
    if (!r.ok) throw new Error(j.error || "Scan failed"); return j;
  }

  async function show(from, payload, me) {
    if (payload.type === "text") {
      const node = addMsg(from, el("div", {}, payload.text), me);
      if (!me) {
        try {
          const fd = new FormData(); fd.append("text", payload.text);
          const rep = await (await fetch("/api/scan", { method: "POST", body: fd })).json();
          if (rep.level && rep.level !== "Low") node.append(warnBox(rep));
        } catch { /* scanning is best effort for plain text */ }
      }
      return;
    }
    // file
    const bytes = unb64(payload.data), blob = new Blob([bytes], { type: payload.mime || "application/octet-stream" });
    const row = el("div", { class: "file" }, `Attachment: ${payload.name} (${fmtSize(bytes.length)})`);
    const node = addMsg(from, row, me);
    if (me) return;
    node.append(el("div", { class: "warn Medium" }, "Scanning before you can open it..."));
    try {
      const rep = await scanBlob(blob, payload.name);
      node.querySelector(".warn").replaceWith(warnBox(rep));
      const open = () => { const a = el("a", { href: URL.createObjectURL(blob), download: payload.name }); document.body.append(a); a.click(); a.remove(); };
      if (rep.level === "High") {
        node.append(el("div", { class: "row" }, el("button", { class: "ghost", onclick: () => { if (confirm("This file looks dangerous. Save it anyway?")) open(); } }, "Save anyway (unsafe)")));
      } else node.append(el("div", { class: "row" }, el("button", { class: "ghost", onclick: open }, "Save file")));
      node.append(el("div", { class: "row" }, el("a", { href: "/api/report/" + rep.id }, "Full scan report")));
    } catch (e) {
      node.querySelector(".warn").replaceWith(el("div", { class: "warn High" }, "Could not scan this file, so it stays locked. " + e.message));
    }
  }

  async function send(payload) {
    if (!st.aes) { alert("Waiting for the other person to join before sending."); return; }
    try { const body = await encrypt(payload); await post("/api/chat/send", { room: st.room, from: st.name, ...body }); poll(); }
    catch (e) { alert(e.message); }
  }
  $("#sendBtn").addEventListener("click", () => { const t = $("#chatText").value.trim(); if (!t) return; $("#chatText").value = ""; send({ type: "text", text: t }); });
  $("#chatText").addEventListener("keydown", e => { if (e.key === "Enter") $("#sendBtn").click(); });
  $("#chatFile").addEventListener("change", async e => {
    const f = e.target.files[0]; e.target.value = ""; if (!f) return;
    if (f.size > 20 * 1048576) { alert("Chat attachments are limited to 20 MB."); return; }
    send({ type: "file", name: f.name, mime: f.type, data: b64(await f.arrayBuffer()) });
  });
})();
