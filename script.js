(function () {
  const form = document.querySelector("#contact-form");
  const status = document.querySelector("#form-status");
  const csrfInput = document.querySelector("#csrf-token");
  const submitButton = form ? form.querySelector("button[type='submit']") : null;

  if (!form || !status || !csrfInput || !submitButton) {
    return;
  }

  const setStatus = (message, type) => {
    status.textContent = message;
    status.className = type ? `form-status ${type}` : "form-status";
  };

  const loadCsrfToken = async () => {
    try {
      const response = await fetch("contact.php?action=csrf", {
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      });
      const data = await response.json();

      if (data.success && data.token) {
        csrfInput.value = data.token;
      }
    } catch (error) {
      setStatus("No se pudo preparar el formulario. Intentalo de nuevo en unos segundos.", "error");
    }
  };

  document.querySelectorAll('a[href^="#"]').forEach((link) => {
    link.addEventListener("click", (event) => {
      const target = document.querySelector(link.getAttribute("href"));

      if (target) {
        event.preventDefault();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setStatus("", "");

    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }

    if (!csrfInput.value) {
      await loadCsrfToken();
    }

    submitButton.disabled = true;
    submitButton.textContent = "Enviando...";

    try {
      const response = await fetch(form.action, {
        method: "POST",
        body: new FormData(form),
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      });
      const data = await response.json();

      setStatus(data.message || "No se pudo enviar el mensaje.", data.success ? "success" : "error");

      if (data.success) {
        form.reset();
      }

      await loadCsrfToken();
    } catch (error) {
      setStatus("No se pudo enviar el mensaje. Intentalo de nuevo mas tarde.", "error");
    } finally {
      submitButton.disabled = false;
      submitButton.textContent = "Enviar";
    }
  });

  loadCsrfToken();
})();
