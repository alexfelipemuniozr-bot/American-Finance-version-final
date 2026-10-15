(function () {
  const TOKEN_KEY = "af_token";
  const USER_KEY = "af_user";
  const API_BASE = window.location.protocol === "file:" ? "http://localhost:3000" : "";

  function getToken() {
    return localStorage.getItem(TOKEN_KEY);
  }

  function getUser() {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY) || "null");
    } catch {
      return null;
    }
  }

  function saveSession(session) {
    localStorage.setItem(TOKEN_KEY, session.token);
    localStorage.setItem(USER_KEY, JSON.stringify(session.user));
  }

  function clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    localStorage.removeItem("currentUser");
  }

  async function request(path, body) {
    try {
      const response = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "No se pudo completar la acción.");
      return data;
    } catch (error) {
      if (error instanceof TypeError) {
        throw new Error("No se pudo conectar con el servidor.");
      }
      throw error;
    }
  }

  async function requireAuth() {
    const token = getToken();
    if (!token) {
      window.location.href = "login.html";
      return null;
    }

    try {
      const response = await fetch(`${API_BASE}/api/auth/me`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) {
        clearSession();
        window.location.href = "login.html";
        return null;
      }

      const data = await response.json();
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));
      return data.user;
    } catch (error) {
      console.error("Auth error:", error);
      clearSession();
      window.location.href = "login.html";
      return null;
    }
  }

  function updateAccountLinks() {
    const user = getUser();
    const loginLinks = document.querySelectorAll(".login-option");
    const registerLinks = document.querySelectorAll(".register-option");

    if (!user) {
      loginLinks.forEach((link) => {
        link.textContent = "Iniciar sesión";
        link.href = "login.html";
      });
      registerLinks.forEach((link) => {
        link.textContent = "Registrarse";
        link.href = "register.html";
      });
      return;
    }

    loginLinks.forEach((link) => {
      link.textContent = `Mi cuenta: ${user.name}`;
      link.href = "home.html";
    });
    registerLinks.forEach((link) => {
      link.textContent = "Cerrar sesión";
      link.href = "#logout";
      link.addEventListener("click", (event) => {
        event.preventDefault();
        clearSession();
        window.location.href = "index.html";
      });
    });
  }

  window.AmericanFinanceAuth = {
    clearSession,
    getToken,
    getUser,
    login: (email, password) => request("/api/auth/login", { email, password }).then((session) => {
      saveSession(session);
      updateAccountLinks();
      return session;
    }),
    register: (name, email, password) => request("/api/auth/register", { name, email, password }).then((session) => {
      saveSession(session);
      updateAccountLinks();
      return session;
    }),
    requireAuth,
    updateAccountLinks,
  };

  document.addEventListener("DOMContentLoaded", () => {
    updateAccountLinks();
    displayUserName();
  });

  function displayUserName() {
    const user = getUser();
    if (!user) return;

    // Mostrar nombre en elemento con id "currentUserName"
    const userNameElement = document.getElementById("currentUserName");
    if (userNameElement) {
      userNameElement.textContent = user.name;
    }

    // Mostrar en cualquier elemento con clase "user-name"
    document.querySelectorAll(".user-name").forEach(el => {
      el.textContent = user.name;
    });
  }
})();
