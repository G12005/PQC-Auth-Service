const state = {
  token: sessionStorage.getItem("pqc_access_token"),
  claims: null,
  mode: "login" // "login" or "register"
};

const { $, decodeToken, formatJson, toBase64Url, setBusy, resetInspectionStates, updateExpiry, createRequest } = window.PqcAuth;
const request = createRequest(new Set(["/auth/login", "/auth/register", "/auth/verify", "/.well-known/pqc-jwks.json"]));

function setMessage(element, message, visible = true) {
  element.textContent = message;
  element.hidden = !visible;
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

function showLogin() {
  $("#dashboard-view").hidden = true;
  $("#login-view").hidden = false;
  setAuthMode("login");
  resetInspectionStates();
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
if (state.token) {
  try {
    // Verify stored token with backend on page load before revealing Page 2
    const body = await request(`/auth/verify?token=${encodeURIComponent(state.token)}`, { method: "POST" });
    if (body.valid) {
      showDashboard();
    } else {
      logout();
    }
  } catch {
    // Invalid or unavailable sessions are returned to the login view.
    logout();
  }
} else {
  showLogin();
}
