const state = {
  token: sessionStorage.getItem("pqc_access_token"),
  claims: null,
  mode: "login" // "login" or "register"
};

const $ = (selector) => document.querySelector(selector);

function setMessage(element, message, visible = true) {
  element.textContent = message;
  element.hidden = !visible;
}

function decodeSegment(segment) {
  const normalized = segment.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  return JSON.parse(decodeURIComponent(atob(padded).split("").map((character) => `%${(`00${character.charCodeAt(0).toString(16)}`).slice(-2)}`).join("")));
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

function setAuthMode(mode) {
  state.mode = mode;
  setMessage($("#login-error"), "", false);
  if (mode === "register") {
    $("#tab-login").classList.remove("active-tab");
    $("#tab-register").classList.add("active-tab");
    $("#form-heading").textContent = "Create Account";
    $("#form-subtext").textContent = "Register new account credentials securely.";
    $("#submit-text").textContent = "Register User";
  } else {
    $("#tab-register").classList.remove("active-tab");
    $("#tab-login").classList.add("active-tab");
    $("#form-heading").textContent = "Access Portal";
    $("#form-subtext").textContent = "Sign in with your account credentials.";
    $("#submit-text").textContent = "Authenticate";
  }
}

function showDashboard() {
  $("#login-view").hidden = true;
  $("#dashboard-view").hidden = false;
  const decoded = decodeToken(state.token);
  state.claims = decoded.claims;
  $("#user-name").textContent = decoded.claims.sub || "operator";
  resetInspectionStates();
  $(".dashboard-heading").focus({ preventScroll: true });
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

function showLogin() {
  $("#dashboard-view").hidden = true;
  $("#login-view").hidden = false;
  setAuthMode("login");
  resetInspectionStates();
}

async function request(url, options = {}) {
  const target = new URL(url, window.location.origin);
  if (target.origin !== window.location.origin) {
    throw new Error("Requests must target this application.");
  }
  const response = await fetch(target, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  const button = $("#submit-btn");
  setMessage($("#login-error"), "", false);
  
  const isRegister = state.mode === "register";
  const endpoint = isRegister ? "/auth/register" : "/auth/login";
  const busyLabel = isRegister ? "Creating account..." : "Authenticating...";

  setBusy(button, true, busyLabel);
  try {
    const body = await request(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: $("#username").value.trim(),
        password: $("#password").value
      }),
    });
    
    // Store token and switch to Page 2 (Dashboard)
    state.token = body.access_token;
    sessionStorage.setItem("pqc_access_token", state.token);
    showDashboard();
  } catch (error) {
    // If login/register fails (e.g. wrong password), clear any old session and remain on Page 1
    logoutWithoutNavigation();
    setMessage($("#login-error"), error.message);
  } finally {
    setBusy(button, false);
  }
}

async function verifyToken(token = state.token, options = {}) {
  const { tamperTest = false } = options;
  const button = tamperTest ? $("#tamper-button") : $("#verify-button");
  setBusy(button, true, "Verifying...");
  if (!tamperTest) {
    $("#verify-status").className = "status-value pending";
    $("#verify-status").textContent = "Checking...";
  }
  try {
    const body = await request(`/auth/verify?token=${encodeURIComponent(token)}`, { method: "POST" });
    if (tamperTest) {
      $("#tamper-status").className = "status-value failure";
      $("#tamper-status").textContent = "Unexpectedly valid";
      $("#tamper-detail").textContent = "The altered copy was accepted by the current backend.";
      $("#demo-message").className = "demo-message failure-message";
      $("#demo-message").textContent = "Unexpected result: the altered token was accepted by the current backend.";
    } else {
      $("#verify-status").className = "status-value success";
      $("#verify-status").textContent = "Signature valid";
      $("#verify-detail").textContent = `Verified subject: ${body.claims.sub || "unknown"}`;
      $("#session-status").textContent = "Current session token verified by backend";
    }
  } catch (error) {
    if (tamperTest) {
      $("#tamper-status").className = "status-value success";
      $("#tamper-status").textContent = "Rejected as expected";
      $("#tamper-detail").textContent = "The altered copy failed verification; the real session is unchanged.";
      $("#demo-message").className = "demo-message success-message";
      $("#demo-message").textContent = "Expected result: the altered token was rejected. The valid session is unchanged.";
    } else {
      $("#verify-status").className = "status-value failure";
      $("#verify-status").textContent = "Verification failed";
      $("#verify-detail").textContent = error.message;
      $("#session-status").textContent = "Current session token rejected by backend";
    }
  } finally {
    setBusy(button, false);
  }
}

async function loadJwks() {
  const button = $("#jwks-button");
  setBusy(button, true, "Loading...");
  try {
    const body = await request("/.well-known/pqc-jwks.json");
    $("#jwks-output").textContent = formatJson(body);
    const key = body.keys?.[0];
    $("#key-status").className = "status-value success";
    $("#key-status").textContent = key?.alg || "Key available";
    $("#key-detail").textContent = `Key ID: ${key?.kid || "not provided"}`;
  } catch (error) {
    $("#key-status").className = "status-value failure";
    $("#key-status").textContent = "Unavailable";
    $("#key-detail").textContent = error.message;
  } finally {
    setBusy(button, false);
  }
}

function revealClaims() {
  const decoded = decodeToken(state.token);
  $("#claims-output").textContent = formatJson({ header: decoded.header, claims: decoded.claims });
  $("#profile-value").className = "profile-value";
  $("#profile-value").textContent = decoded.claims.sub || "Unknown user";
  $("#profile-detail").textContent = `Decoded locally · Issuer: ${decoded.claims.iss || "not provided"}`;
  updateExpiry(decoded.claims);
  $("#profile-button").textContent = "Claims revealed →";
  $("#claims-output").scrollIntoView({ behavior: "smooth", block: "center" });
}

function tamperToken() {
  const decoded = decodeToken(state.token);
  const tamperedPayload = toBase64Url(JSON.stringify({ ...decoded.claims, sub: "tampered-user" }));
  const tampered = `${decoded.parts[0]}.${tamperedPayload}.${decoded.parts[2]}`;
  $("#demo-message").className = "demo-message";
  $("#demo-message").textContent = "Testing an altered copy. The original token remains in session storage.";
  void verifyToken(tampered, { tamperTest: true });
}

function logoutWithoutNavigation() {
  state.token = null;
  state.claims = null;
  sessionStorage.removeItem("pqc_access_token");
}

function logout() {
  logoutWithoutNavigation();
  $("#login-error").hidden = true;
  $("#demo-message").textContent = "";
  $("#demo-message").className = "demo-message";
  showLogin();
}

// Event Listeners
$("#tab-login").addEventListener("click", () => setAuthMode("login"));
$("#tab-register").addEventListener("click", () => setAuthMode("register"));
$("#auth-form").addEventListener("submit", handleAuthSubmit);
$("#verify-button").addEventListener("click", () => verifyToken());
$("#profile-button").addEventListener("click", revealClaims);
$("#jwks-button").addEventListener("click", loadJwks);
$("#tamper-button").addEventListener("click", tamperToken);
$("#logout-button").addEventListener("click", logout);
$("#reset-button").addEventListener("click", logout);

// Initialize Page View
async function initApp() {
  if (state.token) {
    try {
      // Verify stored token with backend on page load before revealing Page 2
      const body = await request(`/auth/verify?token=${encodeURIComponent(state.token)}`, { method: "POST" });
      if (body.valid) {
        showDashboard();
      } else {
        logout();
      }
    } catch (e) {
      logout();
    }
  } else {
    showLogin();
  }
}

void initApp();
