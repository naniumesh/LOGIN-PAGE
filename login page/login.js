// Clear login session when page loads
document.addEventListener("DOMContentLoaded", () => {
  sessionStorage.removeItem("isAdminLoggedIn");

  const loginForm = document.getElementById("loginForm");
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    await login();
  });
});

async function login() {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value.trim();
  const adminType = document.getElementById("adminType").value;
  const errorMsg = document.getElementById("errorMsg");

  if (!username || !password || !adminType) {
    errorMsg.textContent = "Please fill all fields and select admin type.";
    return;
  }

  try {
    const res = await fetch("https://login-page-6jzv.onrender.com/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, adminType })
    });

    const data = await res.json();

    if (res.ok) {
      sessionStorage.setItem("isAdminLoggedIn", "true");
      sessionStorage.setItem("adminType", adminType);
      sessionStorage.setItem("username", username);

      if (adminType === "camp") {
        window.location.href = "https://ncc-campregistration-l6f6.onrender.com/admin%20page/admin.html";
      } else if (adminType === "enroll") {
        window.location.href = "https://lpunccwebsite.z29.web.core.windows.net/ADMIN%20PAGE/admin.html";
      }
    } else {
      errorMsg.textContent = data.message || "Login failed.";
    }

  } catch (err) {
    errorMsg.textContent = "Server error. Please try again.";
    console.error(err);
  }
}

function toggleHomeButtons() {
  const btnContainer = document.getElementById("homeButtons");
  btnContainer.style.display = btnContainer.style.display === "none" ? "flex" : "none";
}

