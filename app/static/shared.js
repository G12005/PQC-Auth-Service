(() => {
  const $ = (selector) => document.querySelector(selector);

  function decodeSegment(segment) {
    const normalized = segment.replaceAll("-", "+").replaceAll("_", "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    const decoded = atob(padded).split("").map((character) => {
      const codePoint = character.codePointAt(0).toString(16).padStart(2, "0");
      return `%${codePoint}`;
    }).join("");
    return JSON.parse(decodeURIComponent(decoded));
  }

  function decodeToken(token) {
    const parts = token.split(".");
    if (parts.length !== 3) throw new Error("The token has an unexpected format.");
    return { header: decodeSegment(parts[0]), claims: decodeSegment(parts[1]), parts };
  }

  function formatJson(value) {
    return JSON.stringify(value, null, 2);
  }

  function toBase64Url(value) {
    const bytes = new TextEncoder().encode(value);
    let binary = "";
    bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
    return btoa(binary).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
  }

  function setBusy(button, busy, label) {
    button.disabled = busy;
    if (busy) {
      button.dataset.originalLabel = button.innerHTML;
      button.innerHTML = `<span>${label}</span>`;
    } else if (button.dataset.originalLabel) {
      button.innerHTML = button.dataset.originalLabel;
    }
  }

  function resetInspectionStates() {
    $("#verify-status").className = "status-value pending";
    $("#verify-status").textContent = "Awaiting action";
    $("#verify-detail").textContent = "Run the backend verification check when ready.";
    $("#profile-value").className = "profile-value masked-value";
    $("#profile-value").textContent = "Hidden";
    $("#profile-detail").textContent = "Claims stay hidden until you choose to read them.";
    $("#key-status").className = "status-value pending";
    $("#key-status").textContent = "Not inspected";
    $("#key-detail").textContent = "Load the backend's public verification key on demand.";
    $("#tamper-status").className = "status-value pending";
    $("#tamper-status").textContent = "Not run";
    $("#tamper-detail").textContent = "Tests an altered copy without changing this session.";
    $("#claims-output").textContent = "Click “Read claims” to reveal the signed token payload.";
    $("#jwks-output").textContent = "Click “Inspect JWKS” to reveal public key metadata.";
    $("#demo-message").textContent = "";
    $("#demo-message").className = "demo-message";
    $("#session-status").textContent = "Session ready — choose a panel to inspect";
  }

  function updateExpiry(claims) {
    const expiry = Number(claims.exp);
    if (!Number.isFinite(expiry)) {
      $("#profile-detail").textContent += " · Expiry unavailable";
      return;
    }
    const date = new Date(expiry * 1000);
    const expired = date.getTime() <= Date.now();
    $("#profile-detail").textContent += expired ? " · Expired" : ` · Expires ${date.toLocaleTimeString()}`;
  }

  function createRequest(allowedRequestPaths) {
    return async function request(url, options = {}) {
      const target = new URL(url, window.location.origin);
      if (target.origin !== window.location.origin || !allowedRequestPaths.has(target.pathname)) {
        throw new Error("Requests must target an approved application endpoint.");
      }
      const response = await fetch(target, options);
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
      return body;
    };
  }

  window.PqcAuth = Object.freeze({
    $,
    decodeToken,
    formatJson,
    toBase64Url,
    setBusy,
    resetInspectionStates,
    updateExpiry,
    createRequest
  });
})();
