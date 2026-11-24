// Single-page screen navigation: no browser page navigation is used.
const screens = ["roleScreen","adminLoginScreen","userLoginScreen","userRegisterScreen","adminDashboardScreen","userDashboardScreen"];
function showScreen(id) {
  screens.forEach(screenId => document.getElementById(screenId).hidden = screenId !== id);
  document.body.classList.toggle("spa-center", ["roleScreen","adminLoginScreen","userLoginScreen","userRegisterScreen"].includes(id));
  if (id === "adminDashboardScreen") loadStudents();
  if (id === "userDashboardScreen") loadUserProfile();
}
// API-based Admin / User selection
async function selectRole(role) {
    try {
        const response = await fetch("/api/select-role", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ role: role })
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Unable to select role");
        }

        showScreen(data.screen);

    } catch (error) {
        alert(error.message);
    }
}

document.getElementById("chooseAdmin").addEventListener("click", () => {
    selectRole("admin");
});

document.getElementById("chooseUser").addEventListener("click", () => {
    selectRole("user");
});
document.querySelectorAll("[data-screen]").forEach(btn => btn.addEventListener("click", () => showScreen(btn.dataset.screen)));
document.getElementById("goRegister").addEventListener("click", () => showScreen("userRegisterScreen"));
document.getElementById("backToUserLogin").addEventListener("click", () => showScreen("userLoginScreen"));

// Admin authentication and API calls
const studentApi = "/students";
const getAdminToken = () => sessionStorage.getItem("studentToken");
function clearAdminSession() { sessionStorage.removeItem("studentToken"); }
async function adminApi(url, options = {}) {
  const token = getAdminToken();
  if (!token) { showScreen("adminLoginScreen"); throw new Error("Please login first"); }
  const headers = {...(options.headers || {}), Authorization: "Bearer " + token};
  const response = await fetch(url, {...options, headers});
  if (response.status === 401) { clearAdminSession(); showScreen("adminLoginScreen"); throw new Error("Session expired. Please login again."); }
  return response;
}
document.getElementById("adminLoginForm").addEventListener("submit", async event => {
  event.preventDefault();
  const button = document.getElementById("adminLoginButton"), message = document.getElementById("adminLoginMessage");
  button.disabled = true; message.textContent = "";
  try {
    const response = await fetch("/login", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({email:document.getElementById("adminEmail").value.trim(), password:document.getElementById("adminPassword").value})});
    const data = await response.json();
    if (!response.ok || !data.token) throw new Error(data.error || "Login failed");
    sessionStorage.setItem("studentToken", data.token); showScreen("adminDashboardScreen");
  } catch(error) { message.textContent = error.message || "Unable to connect to server"; }
  finally { button.disabled = false; }
});
async function loadStudents() {
  if (!getAdminToken()) return;
  try {
    const response = await adminApi(studentApi); const students = await response.json();
    if (!response.ok) throw new Error(students.error || "Unable to load students");
    const table = document.getElementById("studentTable"); table.innerHTML = "";
    students.forEach((student,index) => {
      const row = document.createElement("tr");
      [student.id,student.roll_no,student.name,student.email,student.mobile,student.department,student.year].forEach(value => { const cell=document.createElement("td"); cell.textContent=value ?? ""; row.appendChild(cell); });
      // Keep ID as the first displayed column; serial number is not required.
      const action=document.createElement("td"); const edit=document.createElement("button"); edit.textContent="Edit"; edit.onclick=()=>editStudent(student);
      const del=document.createElement("button"); del.textContent="Delete"; del.onclick=()=>deleteStudent(student.id); action.append(edit,del); row.appendChild(action); table.appendChild(row);
    });
  } catch(error) { if (error.message !== "Please login first") alert(error.message); }
}
// Correct the row columns to match the existing table (ID, roll, name, email, mobile, dept, year, action).
async function getStudent(id) { const response=await adminApi(`${studentApi}/${id}`); const data=await response.json(); if(!response.ok) throw new Error(data.error||"Student not found"); return data; }
document.getElementById("searchButton").addEventListener("click", async()=>{
  const id=document.getElementById("searchStudentId").value.trim(), result=document.getElementById("singleStudentResult"); result.innerHTML="";
  if(!id || Number(id)<=0){alert("Please enter a valid Student ID");return;}
  try { const student=await getStudent(id); const heading=document.createElement("h3"); heading.textContent="Student Details"; const table=document.createElement("table");
    [["ID",student.id],["Roll Number",student.roll_no],["Name",student.name],["Email",student.email],["Mobile",student.mobile],["Department",student.department],["Year",student.year]].forEach(([label,value])=>{const row=document.createElement("tr"),th=document.createElement("th"),td=document.createElement("td");th.textContent=label;td.textContent=value??"";row.append(th,td);table.appendChild(row);}); result.append(heading,table);
  } catch(error){alert(error.message);}
});
document.getElementById("showAllButton").addEventListener("click",()=>{document.getElementById("singleStudentResult").innerHTML="";document.getElementById("searchStudentId").value="";loadStudents();});
document.getElementById("studentForm").addEventListener("submit",async event=>{
  event.preventDefault(); const student={roll_no:document.getElementById("roll_no").value.trim(),name:document.getElementById("name").value.trim(),email:document.getElementById("email").value.trim(),mobile:document.getElementById("mobile").value.trim(),department:document.getElementById("department").value.trim(),year:Number(document.getElementById("year").value)};
  try { const response=await adminApi(studentApi,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(student)}); const data=await response.json(); alert(data.message||data.error||"Request completed"); if(response.ok){event.target.reset();loadStudents();} } catch(error){alert(error.message);}
});
async function editStudent(student){
  const name=prompt("Enter new name:",student.name); if(name===null||!name.trim())return;
  const email=prompt("Enter new email:",student.email); if(email===null||!email.trim())return;
  const mobile=prompt("Enter new mobile number:",student.mobile||""); if(mobile===null||!mobile.trim())return;
  try { const response=await adminApi(`${studentApi}/${student.id}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({...student,name:name.trim(),email:email.trim(),mobile:mobile.trim()})}); const data=await response.json(); alert(data.message||data.error||"Update completed"); if(response.ok)loadStudents(); } catch(error){alert(error.message);}
}
async function deleteStudent(id){if(!confirm("Are you sure you want to delete this student?"))return;try{const response=await adminApi(`${studentApi}/${id}`,{method:"DELETE"});const data=await response.json();alert(data.message||data.error||"Delete completed");if(response.ok)loadStudents();}catch(error){alert(error.message);}}
document.getElementById("adminLogoutButton").addEventListener("click",async()=>{
  if(!confirm("Are you sure you want to logout?"))return; const token=getAdminToken();
  try{if(token)await fetch("/logout",{method:"POST",headers:{Authorization:"Bearer "+token}});}catch(error){console.error(error);}finally{clearAdminSession();showScreen("roleScreen");}
});

// User registration/login/profile APIs
const getUserToken=()=>localStorage.getItem("userToken");
document.getElementById("userRegisterForm").addEventListener("submit",async event=>{
  event.preventDefault(); const email=document.getElementById("registerEmail").value.trim(),password=document.getElementById("registerPassword").value,confirm=document.getElementById("confirmPassword").value;
  const message=document.getElementById("registerMessage"),button=document.getElementById("registerButton"); message.style.color="red";
  if(password!==confirm){message.textContent="Passwords do not match!";return;}
  button.disabled=true;message.textContent="";
  try{const response=await fetch("/user/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,password})});const data=await response.json();if(!response.ok)throw new Error(data.error||"Registration failed");message.style.color="green";message.textContent="Registration successful! Please login.";event.target.reset();setTimeout(()=>showScreen("userLoginScreen"),1200);}catch(error){message.textContent=error.message;}finally{button.disabled=false;}
});
document.getElementById("userLoginForm").addEventListener("submit",async event=>{
  event.preventDefault();const button=document.getElementById("userLoginButton"),message=document.getElementById("userLoginMessage");button.disabled=true;message.textContent="";
  try{const response=await fetch("/user/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:document.getElementById("userLoginEmail").value.trim(),password:document.getElementById("userLoginPassword").value})});const data=await response.json();if(!response.ok)throw new Error(data.error||"Login failed");localStorage.setItem("userToken",data.token);localStorage.setItem("userEmail",data.email);showScreen("userDashboardScreen");}catch(error){message.textContent=error.message;}finally{button.disabled=false;}
});
let originalProfileName="";
async function loadUserProfile(){
  const token=getUserToken();if(!token){showScreen("userLoginScreen");return;}
  try{const response=await fetch("/user/me",{headers:{Authorization:"Bearer "+token}});const data=await response.json();if(response.status===401){localStorage.removeItem("userToken");localStorage.removeItem("userEmail");showScreen("userLoginScreen");return;}if(!response.ok)throw new Error(data.error||"Unable to load profile");
    const fields={profileStudentId:data.id,profileRollNo:data.roll_no,profileName:data.name,profileEmail:data.email,profileMobile:data.mobile,profileDepartment:data.department,profileYear:data.year};Object.entries(fields).forEach(([id,value])=>document.getElementById(id).value=value??"");originalProfileName=data.name??"";document.getElementById("profileMessage").textContent="";
  }catch(error){document.getElementById("profileMessage").textContent=error.message;}
}
function finishNameEdit(){document.getElementById("profileName").disabled=true;document.getElementById("editNameButton").hidden=false;document.getElementById("saveNameButton").hidden=true;document.getElementById("cancelNameButton").hidden=true;}
document.getElementById("editNameButton").addEventListener("click",()=>{document.getElementById("profileName").disabled=false;document.getElementById("editNameButton").hidden=true;document.getElementById("saveNameButton").hidden=false;document.getElementById("cancelNameButton").hidden=false;document.getElementById("profileName").focus();});
document.getElementById("cancelNameButton").addEventListener("click",()=>{document.getElementById("profileName").value=originalProfileName;document.getElementById("profileMessage").textContent="";finishNameEdit();});
document.getElementById("saveNameButton").addEventListener("click",async()=>{
  const name=document.getElementById("profileName").value.trim(),message=document.getElementById("profileMessage");if(!name){message.textContent="Name cannot be empty";return;}
  try{const response=await fetch("/user/me",{method:"PATCH",headers:{"Content-Type":"application/json",Authorization:"Bearer "+getUserToken()},body:JSON.stringify({name})});const data=await response.json();if(response.status===401){localStorage.removeItem("userToken");localStorage.removeItem("userEmail");showScreen("userLoginScreen");return;}if(!response.ok)throw new Error(data.error||"Unable to update name");originalProfileName=name;message.textContent="Name updated successfully!";finishNameEdit();}catch(error){message.textContent=error.message;}
});
document.getElementById("userLogoutButton").addEventListener("click",async()=>{if(!confirm("Are you sure you want to logout?"))return;const token=getUserToken();try{if(token)await fetch("/user/logout",{method:"POST",headers:{Authorization:"Bearer "+token}});}catch(error){console.error(error);}finally{localStorage.removeItem("userToken");localStorage.removeItem("userEmail");showScreen("roleScreen");}});

sessionStorage.removeItem("studentToken");
localStorage.removeItem("userToken");
localStorage.removeItem("userEmail");

showScreen("roleScreen");