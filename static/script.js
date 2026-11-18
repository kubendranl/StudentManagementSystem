
const apiUrl = "/students";

let sessionExpiryTimer = null;
let sessionExpiryTime = null;
let redirectingToLogin = false;

// ---------------- TOKEN FUNCTIONS ----------------

function getToken() {
    return sessionStorage.getItem("studentToken");
}

function decodeToken(token) {
    try {
        const payload = token.split(".")[1];

        if (!payload) {
            return null;
        }

        const base64 = payload
            .replace(/-/g, "+")
            .replace(/_/g, "/");

        return JSON.parse(atob(base64));
    } catch (error) {
        console.error("Token decoding failed:", error);
        return null;
    }
}

function redirectToLogin(message = "") {

    if (redirectingToLogin) return;

    redirectingToLogin = true;

    if (sessionExpiryTimer) {
        clearTimeout(sessionExpiryTimer);
    }

    sessionStorage.removeItem("studentToken");

    if (message) {
        alert(message);
    }

    window.location.href = "/login-page";
}

// ---------------- AUTOMATIC SESSION EXPIRY ----------------

function checkSessionExpiry() {

    const token = getToken();

    if (!token) {
        return false;
    }

    const payload = decodeToken(token);

    if (!payload || !payload.exp) {
        redirectToLogin("Invalid session. Please login again.");
        return false;
    }

    sessionExpiryTime = payload.exp * 1000;

    if (Date.now() >= sessionExpiryTime) {

        redirectToLogin(
            "Your session has expired. Please login again."
        );

        return false;
    }

    return true;
}

function setupSessionExpiry() {

    const token = getToken();

    if (!token) {
        return;
    }

    if (!checkSessionExpiry()) {
        return;
    }

    const remainingTime = sessionExpiryTime - Date.now();

    if (sessionExpiryTimer) {
        clearTimeout(sessionExpiryTimer);
    }

    sessionExpiryTimer = setTimeout(() => {

        redirectToLogin(
            "Your session has expired. Please login again."
        );

    }, remainingTime);
}

// Check expiry when returning to the browser tab
document.addEventListener("visibilitychange", function() {

    if (!document.hidden && getToken()) {
        checkSessionExpiry();
    }

});


// ---------------- API REQUEST WITH JWT ----------------

async function apiRequest(url, options = {}) {

    const token = getToken();

    if (!token) {
        redirectToLogin();
        throw new Error("Please login first");
    }

    if (!checkSessionExpiry()) {
        throw new Error("Session expired");
    }

    const headers = {
        ...options.headers,
        "Authorization": "Bearer " + token
    };

    const response = await fetch(url, {
        ...options,
        headers
    });

    if (response.status === 401) {

        redirectToLogin(
            "Your session expired or another admin logged in. Please login again."
        );

        throw new Error("Session expired");
    }

    return response;
}


// ---------------- LOAD STUDENTS ----------------

async function loadStudents() {

    try {

        const response = await apiRequest(apiUrl);

        const students = await response.json();

        if (!response.ok) {
            alert(students.error || "Unable to load students");
            return;
        }

        const table = document.getElementById("studentTable");

        if (!table) return;

        table.innerHTML = "";

        students.forEach((student, index) => {

            const row = document.createElement("tr");

            [
                index + 1,
                student.roll_no,
                student.name,
                student.email,
                student.mobile,
                student.department,
                student.year
            ].forEach(value => {

                const cell = document.createElement("td");
                cell.textContent = value ?? "";
                row.appendChild(cell);

            });

            const actionCell = document.createElement("td");

            const editButton = document.createElement("button");
            editButton.textContent = "Edit";
            editButton.onclick = () => editStudent(student);

            const deleteButton = document.createElement("button");
            deleteButton.textContent = "Delete";
            deleteButton.onclick = () => deleteStudent(student.id);

            actionCell.append(editButton, deleteButton);
            row.appendChild(actionCell);

            table.appendChild(row);

        });

    } catch (error) {

        console.error(error);

        if (
            error.message !== "Please login first" &&
            error.message !== "Session expired"
        ) {
            alert("Cannot connect to Flask server!");
        }

    }
}


// ---------------- GET SINGLE STUDENT ----------------

async function getStudentById(id) {

    const response = await apiRequest(`${apiUrl}/${id}`);

    const student = await response.json();

    if (!response.ok) {
        return {
            error: student.error || "Unable to fetch student",
            status: response.status
        };
    }

    return {
        student: student
    };
}


// ---------------- SEARCH STUDENT BUTTON ----------------

const searchButton = document.getElementById("searchButton");

if (searchButton) {

    searchButton.addEventListener("click", async function() {

        const id = document.getElementById("searchStudentId").value.trim();
        const result = document.getElementById("singleStudentResult");

        if (!id || Number(id) <= 0) {
            alert("Please enter a valid Student ID");
            return;
        }

        try {

            const data = await getStudentById(id);

            result.innerHTML = "";

            if (data.error) {

                const message = document.createElement("p");
                message.textContent = data.error;
                result.appendChild(message);

                return;
            }

            const student = data.student;

            const heading = document.createElement("h3");
            heading.textContent = "Student Details";

            const table = document.createElement("table");

            const fields = [
                ["ID", student.id],
                ["Roll Number", student.roll_no],
                ["Name", student.name],
                ["Email", student.email],
                ["Mobile", student.mobile],
                ["Department", student.department],
                ["Year", student.year]
            ];

            fields.forEach(([label, value]) => {

                const row = document.createElement("tr");
                const th = document.createElement("th");
                const td = document.createElement("td");

                th.textContent = label;
                td.textContent = value ?? "";

                row.append(th, td);
                table.appendChild(row);

            });

            result.append(heading, table);

        } catch (error) {

            console.error("Search error:", error);

            if (
                error.message !== "Please login first" &&
                error.message !== "Session expired"
            ) {
                alert("Unable to connect to the server!");
            }

        }

    });

}


// ---------------- SHOW ALL STUDENTS ----------------

const showAllButton = document.getElementById("showAllButton");

if (showAllButton) {

    showAllButton.addEventListener("click", function() {

        document.getElementById("singleStudentResult").innerHTML = "";

        document.getElementById("searchStudentId").value = "";

        loadStudents();

    });

}


// ---------------- ADD STUDENT ----------------

const studentForm = document.getElementById("studentForm");

if (studentForm) {

    studentForm.addEventListener("submit", async function(event) {

        event.preventDefault();

        const student = {

            roll_no: document.getElementById("roll_no").value.trim(),
            name: document.getElementById("name").value.trim(),
            email: document.getElementById("email").value.trim(),
            mobile: document.getElementById("mobile").value.trim(),
            department: document.getElementById("department").value.trim(),
            year: Number(document.getElementById("year").value)

        };

        try {

            const response = await apiRequest(apiUrl, {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify(student)

            });

            const result = await response.json();

            alert(result.message || result.error);

            if (response.ok) {
                this.reset();
                loadStudents();
            }

        } catch (error) {

            console.error(error);

            if (
                error.message !== "Please login first" &&
                error.message !== "Session expired"
            ) {
                alert("Cannot connect to Flask server!");
            }

        }

    });

}


// ---------------- UPDATE STUDENT ----------------

async function editStudent(student) {

    const name = prompt("Enter new name:", student.name);

    if (name === null || name.trim() === "") return;

    const email = prompt("Enter new email:", student.email);

    if (email === null || email.trim() === "") return;

    const mobile = prompt("Enter new mobile number:", student.mobile || "");

    if (mobile === null || mobile.trim() === "") return;

    try {

        const response = await apiRequest(`${apiUrl}/${student.id}`, {

            method: "PUT",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({

                roll_no: student.roll_no,
                name: name.trim(),
                email: email.trim(),
                mobile: mobile.trim(),
                department: student.department,
                year: student.year

            })

        });

        const result = await response.json();

        alert(result.message || result.error);

        if (response.ok) {
            loadStudents();
        }

    } catch (error) {

        console.error(error);

        if (
            error.message !== "Please login first" &&
            error.message !== "Session expired"
        ) {
            alert("Cannot connect to Flask server!");
        }

    }

}


// ---------------- DELETE STUDENT ----------------

async function deleteStudent(id) {

    if (!confirm("Are you sure you want to delete this student?")) {
        return;
    }

    try {

        const response = await apiRequest(`${apiUrl}/${id}`, {

            method: "DELETE"

        });

        const result = await response.json();

        alert(result.message || result.error);

        if (response.ok) {
            loadStudents();
        }

    } catch (error) {

        console.error(error);

        if (
            error.message !== "Please login first" &&
            error.message !== "Session expired"
        ) {
            alert("Cannot connect to Flask server!");
        }

    }

}


// ---------------- LOGOUT ----------------

const logoutButton = document.getElementById("logoutButton");

if (logoutButton) {

    logoutButton.addEventListener("click", async function() {

        if (!confirm("Are you sure you want to logout?")) {
            return;
        }

        const token = getToken();

        try {

            if (token) {

                const response = await fetch("/logout", {

                    method: "POST",

                    headers: {
                        "Authorization": "Bearer " + token
                    }

                });

                if (!response.ok) {
                    console.error("Logout API failed");
                }

            }

        } catch (error) {

            console.error("Logout error:", error);

        } finally {

            if (sessionExpiryTimer) {
                clearTimeout(sessionExpiryTimer);
            }

            sessionStorage.removeItem("studentToken");

            window.location.href = "/login-page";

        }

    });

}


// ---------------- INITIAL LOAD ----------------

setupSessionExpiry();

loadStudents();
