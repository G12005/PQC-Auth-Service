const state = {
  mode: "login" // "login" or "register"
};

const $ = (selector) => document.querySelector(selector);

function setMessage(element, message, visible = true) {
  element.textContent = message;
  element.hidden = !visible;
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
    $("#form-heading").textContent = "Sign In";
    $("#form-subtext").textContent = "Sign in with your account credentials.";
    $("#submit-text").textContent = "Authenticate";
  }
}

async function request(url, options = {}) {
  const response = await fetch(url, options);
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
    
    // Store access token and redirect to Page 2 (Dashboard)
    sessionStorage.setItem("pqc_access_token", body.access_token);
    window.location.href = "/dashboard";
  } catch (error) {
    // Authentication or registration failed (e.g. wrong password)
    // Clear any token and display error message on Page 1
    sessionStorage.removeItem("pqc_access_token");
    setMessage($("#login-error"), error.message);
  } finally {
    setBusy(button, false);
  }
}

// Event Listeners
$("#tab-login").addEventListener("click", () => setAuthMode("login"));
$("#tab-register").addEventListener("click", () => setAuthMode("register"));
$("#auth-form").addEventListener("submit", handleAuthSubmit);

// Check if user is already logged in with a valid token
async function checkExistingSession() {
  const token = sessionStorage.getItem("pqc_access_token");
  if (token) {
    try {
      const res = await request(`/auth/verify?token=${encodeURIComponent(token)}`, { method: "POST" });
      if (res.valid) {
        window.location.href = "/dashboard";
      } else {
        sessionStorage.removeItem("pqc_access_token");
      }
    } catch {
      sessionStorage.removeItem("pqc_access_token");
    }
  }
}

checkExistingSession();
