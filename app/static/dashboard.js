const state = {
  token: sessionStorage.getItem("pqc_access_token"),
  claims: null
};

const { $, decodeToken, formatJson, toBase64Url, setBusy, resetInspectionStates, updateExpiry, createRequest } = window.PqcAuth;
const request = createRequest(new Set(["/auth/verify", "/.well-known/pqc-jwks.json"]));

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

function logout() {
  state.token = null;
  state.claims = null;
  sessionStorage.removeItem("pqc_access_token");
  window.location.href = "/";
}

// Event Listeners
$("#verify-button").addEventListener("click", () => verifyToken());
$("#profile-button").addEventListener("click", revealClaims);
$("#jwks-button").addEventListener("click", loadJwks);
$("#tamper-button").addEventListener("click", tamperToken);
$("#logout-button").addEventListener("click", logout);
$("#reset-button").addEventListener("click", logout);

// Initialize Dashboard Page
async function initDashboard() {
  if (!state.token) {
    logout();
    return;
  }

  try {
    const res = await request(`/auth/verify?token=${encodeURIComponent(state.token)}`, { method: "POST" });
    if (!res.valid) {
      logout();
      return;
    }
    const decoded = decodeToken(state.token);
    state.claims = decoded.claims;
    $("#user-name").textContent = decoded.claims.sub || "operator";
    resetInspectionStates();
  } catch {
    // Invalid or unavailable sessions are returned to the login view.
    logout();
  }
}

await initDashboard();
