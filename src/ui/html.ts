import { FlarehookConfig } from "../types.js";

export function getInspectorHtml(config: FlarehookConfig): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>flarehook inspector</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --green: #3fb950;
      --red: #f85149;
      --yellow: #d29922;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
    header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 20px; display: flex; align-items: center; justify-content: space-between; }
    .brand { display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 16px; color: #fff; }
    .status-pill { font-size: 12px; background: rgba(63, 185, 80, 0.15); color: var(--green); padding: 4px 10px; border-radius: 12px; font-weight: 500; }
    .btn { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 6px; font-size: 12px; cursor: pointer; transition: all 0.15s; }
    .btn:hover { border-color: var(--text-muted); color: #fff; }
    .btn-primary { background: #238636; border-color: rgba(240, 246, 252, 0.1); color: #fff; }
    .btn-primary:hover { background: #2ea043; }
    .main { display: flex; flex: 1; overflow: hidden; }
    .sidebar { width: 380px; border-right: 1px solid var(--border); display: flex; flex-direction: column; background: var(--surface); }
    .sidebar-header { padding: 10px 14px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: var(--text-muted); }
    .req-list { flex: 1; overflow-y: auto; }
    .req-item { padding: 12px 14px; border-bottom: 1px solid var(--border); cursor: pointer; display: flex; flex-direction: column; gap: 6px; }
    .req-item:hover, .req-item.active { background: #1f242c; }
    .req-top { display: flex; align-items: center; justify-content: space-between; font-size: 13px; font-family: var(--font-mono); }
    .method { font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 11px; }
    .method-POST { background: rgba(88, 166, 255, 0.15); color: var(--accent); }
    .method-GET { background: rgba(63, 185, 80, 0.15); color: var(--green); }
    .status-badge { font-weight: 600; font-size: 12px; }
    .status-2xx { color: var(--green); }
    .status-4xx, .status-5xx { color: var(--red); }
    .req-path { font-family: var(--font-mono); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: #fff; }
    .req-time { font-size: 11px; color: var(--text-muted); }
    .detail { flex: 1; display: flex; flex-direction: column; background: var(--bg); overflow-y: auto; padding: 20px; }
    .empty-state { display: flex; align-items: center; justify-content: center; height: 100%; color: var(--text-muted); font-size: 14px; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .card-title { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
    .code-box { background: #090d13; border: 1px solid var(--border); border-radius: 6px; padding: 12px; font-family: var(--font-mono); font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 400px; overflow-y: auto; }
    .kv-table { width: 100%; font-family: var(--font-mono); font-size: 12px; border-collapse: collapse; }
    .kv-table td { padding: 6px 8px; border-bottom: 1px solid rgba(48, 54, 61, 0.5); }
    .kv-key { color: var(--accent); width: 220px; word-break: break-all; }
    .kv-val { color: var(--text); word-break: break-all; }
    .modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); align-items: center; justify-content: center; z-index: 100; }
    .modal.open { display: flex; }
    .modal-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; width: 550px; max-width: 90vw; padding: 20px; }
    .form-group { margin-bottom: 14px; }
    .form-group label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 6px; }
    .form-control { width: 100%; background: #090d13; border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px; color: #fff; font-family: var(--font-mono); font-size: 12px; }
    .warning-box { background: rgba(210, 153, 34, 0.15); border: 1px solid var(--yellow); color: var(--yellow); padding: 8px 12px; border-radius: 6px; font-size: 12px; margin-bottom: 14px; }
  </style>
</head>
<body>
  <header>
    <div class="brand">flarehook <span class="status-pill">${config.targetProtocol}//${config.targetHost}:${config.targetPort}</span></div>
    <div><button class="btn" id="clearBtn">Clear History</button></div>
  </header>
  <div class="main">
    <div class="sidebar">
      <div class="sidebar-header"><span id="reqCount">0 requests</span><span>SSE Connected</span></div>
      <div class="req-list" id="reqList"></div>
    </div>
    <div class="detail" id="detailPane">
      <div class="empty-state">Select a request from the sidebar to inspect payload</div>
    </div>
  </div>

  <div class="modal" id="replayModal">
    <div class="modal-box">
      <h3 style="margin-bottom: 12px; font-size: 15px; color: #fff;">Webhook Replay & HMAC Re-Signer</h3>
      <div class="warning-box">Signature timestamp will be auto-refreshed to Date.now() if a preset is selected.</div>
      <div class="form-group">
        <label>HMAC Re-Signing Preset</label>
        <select class="form-control" id="presetSelect">
          <option value="">None (Standard Replay)</option>
          <option value="stripe">Stripe (stripe-signature)</option>
          <option value="github">GitHub (x-hub-signature-256)</option>
          <option value="midtrans">Midtrans (signature_key SHA-512)</option>
        </select>
      </div>
      <div class="form-group" id="secretGroup" style="display:none;">
        <label>Webhook Signing Secret</label>
        <input type="text" class="form-control" id="webhookSecret" placeholder="e.g. whsec_... or Server Key">
      </div>
      <div class="form-group">
        <label>Custom Body (Optional Override)</label>
        <textarea class="form-control" id="customBody" rows="5"></textarea>
      </div>
      <div style="display:flex; justify-content: flex-end; gap: 8px; margin-top: 16px;">
        <button class="btn" id="closeModalBtn">Cancel</button>
        <button class="btn btn-primary" id="executeReplayBtn">Dispatch Replay</button>
      </div>
    </div>
  </div>

  <script>
    let activeId = null;
    let requests = [];
    let isRevealed = false;
    let currentDetailData = null;

    const reqListEl = document.getElementById("reqList");
    const detailPaneEl = document.getElementById("detailPane");
    const reqCountEl = document.getElementById("reqCount");
    const replayModal = document.getElementById("replayModal");
    const presetSelect = document.getElementById("presetSelect");
    const secretGroup = document.getElementById("secretGroup");

    presetSelect.addEventListener("change", () => {
      secretGroup.style.display = presetSelect.value ? "block" : "none";
    });

    document.getElementById("closeModalBtn").onclick = () => replayModal.classList.remove("open");
    document.getElementById("clearBtn").onclick = async () => {
      await fetch("/api/clear", { method: "POST" });
      requests = [];
      renderList();
      detailPaneEl.replaceChildren();
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "History cleared";
      detailPaneEl.appendChild(empty);
    };

    function renderList() {
      reqCountEl.textContent = requests.length + " requests";
      reqListEl.replaceChildren();

      requests.forEach(r => {
        const item = document.createElement("div");
        item.className = "req-item" + (r.id === activeId ? " active" : "");
        item.onclick = () => { isRevealed = false; loadDetail(r.id); };

        const top = document.createElement("div");
        top.className = "req-top";

        const m = document.createElement("span");
        m.className = "method method-" + r.method;
        m.textContent = r.method;

        const s = document.createElement("span");
        s.className = "status-badge status-" + (r.statusCode ? Math.floor(r.statusCode/100) + "xx" : "loading");
        s.textContent = r.statusCode ? String(r.statusCode) : "...";

        top.append(m, s);

        const p = document.createElement("div");
        p.className = "req-path";
        p.textContent = r.rawUrl;

        const t = document.createElement("div");
        t.className = "req-time";
        t.textContent = new Date(r.timestamp).toLocaleTimeString() + (r.durationMs !== undefined ? " (" + r.durationMs + "ms)" : "");

        item.append(top, p, t);
        reqListEl.appendChild(item);
      });
    }

    async function loadDetail(id) {
      activeId = id;
      renderList();
      const res = await fetch("/api/request/" + id + (isRevealed ? "?reveal=1" : ""));
      if (!res.ok) return;
      currentDetailData = await res.json();
      renderDetail(currentDetailData);
    }

    function renderDetail(data) {
      detailPaneEl.replaceChildren();

      const topCard = document.createElement("div");
      topCard.className = "card";
      const topTitle = document.createElement("div");
      topTitle.className = "card-title";
      topTitle.textContent = data.request.method + " " + data.request.rawUrl;

      const btnGroup = document.createElement("div");
      btnGroup.style.display = "flex";
      btnGroup.style.gap = "8px";

      const revealBtn = document.createElement("button");
      revealBtn.className = "btn";
      revealBtn.id = "revealBtn";
      revealBtn.textContent = isRevealed ? "Hide Secrets" : "Reveal Secrets";
      revealBtn.onclick = () => {
        isRevealed = !isRevealed;
        loadDetail(data.id);
      };
      btnGroup.appendChild(revealBtn);

      const replayBtn = document.createElement("button");
      replayBtn.className = "btn btn-primary";
      replayBtn.textContent = "Replay Webhook";
      if (data.request.isTruncated) {
        replayBtn.disabled = true;
        replayBtn.textContent = "Replay Disabled (>1MB)";
      } else {
        replayBtn.onclick = () => openReplay(data);
      }
      btnGroup.appendChild(replayBtn);

      topTitle.appendChild(btnGroup);
      topCard.appendChild(topTitle);
      detailPaneEl.appendChild(topCard);

      // Headers table
      const headCard = document.createElement("div");
      headCard.className = "card";
      const headTitle = document.createElement("div");
      headTitle.className = "card-title";
      headTitle.textContent = "Request Headers";
      headCard.appendChild(headTitle);

      const table = document.createElement("table");
      table.className = "kv-table";
      for (const [k, v] of Object.entries(data.request.headers)) {
        const row = document.createElement("tr");
        const kTd = document.createElement("td");
        kTd.className = "kv-key";
        kTd.textContent = k;
        const vTd = document.createElement("td");
        vTd.className = "kv-val";
        vTd.textContent = Array.isArray(v) ? v.join(", ") : String(v || "");
        row.append(kTd, vTd);
        table.appendChild(row);
      }
      headCard.appendChild(table);
      detailPaneEl.appendChild(headCard);

      // Body viewer
      const bodyCard = document.createElement("div");
      bodyCard.className = "card";
      const bodyTitle = document.createElement("div");
      bodyTitle.className = "card-title";
      bodyTitle.textContent = "Request Payload (" + data.request.byteSize + " bytes)";
      bodyCard.appendChild(bodyTitle);

      const codeBox = document.createElement("pre");
      codeBox.className = "code-box";
      codeBox.textContent = data.request.bodyText || "(Empty body)";
      bodyCard.appendChild(codeBox);
      detailPaneEl.appendChild(bodyCard);
    }

    function openReplay(data) {
      const originalText = data.request.bodyText || "";
      document.getElementById("customBody").value = originalText;
      replayModal.classList.add("open");

      document.getElementById("executeReplayBtn").onclick = async () => {
        const preset = presetSelect.value;
        const secret = document.getElementById("webhookSecret").value;
        const currentText = document.getElementById("customBody").value;

        // Only send customBodyText if user actually edited the textarea
        const bodyChanged = currentText !== originalText;

        const res = await fetch("/api/replay/" + data.id, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            reSignPreset: preset || undefined,
            webhookSecret: secret || undefined,
            customBodyText: bodyChanged ? currentText : undefined
          })
        });

        const reply = await res.json();
        replayModal.classList.remove("open");
        alert(res.ok ? "Replayed successfully! Status: " + reply.statusCode : "Replay failed: " + reply.error);
      };
    }

    // SSE Stream
    const evtSource = new EventSource("/api/sse");
    evtSource.onmessage = e => {
      const item = JSON.parse(e.data);
      const existingIdx = requests.findIndex(r => r.id === item.id);
      if (existingIdx >= 0) {
        requests[existingIdx] = item;
      } else {
        requests.unshift(item);
      }
      renderList();
      if (activeId === item.id) loadDetail(item.id);
    };

    fetch("/api/history").then(r => r.json()).then(data => {
      requests = data;
      renderList();
    });
  </script>
</body>
</html>`;
}
