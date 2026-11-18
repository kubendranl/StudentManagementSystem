const loginForm = document.getElementById("loginForm");

if (loginForm) {
    loginForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const email = document.getElementById("email").value.trim();
        const password = document.getElementById("password").value;

        try {
            const response = await fetch("/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    email: email,
                    password: password
                })
            });

            const data = await response.json();

            if (response.ok && data.token) {
                sessionStorage.setItem("studentToken", data.token);
                window.location.href = "/admin/dashboard";
            } else {
                alert(data.error || "Invalid email or password");
            }

        } catch (error) {
            console.error("Login error:", error);
            alert("Unable to connect to the server");
        }
    });
}