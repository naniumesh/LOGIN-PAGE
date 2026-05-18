// ======================================
// CAPITAL LETTER FUNCTION
// ======================================

function toCaps(text){

    return text.toUpperCase().trim();
}

document.addEventListener("DOMContentLoaded", async function () {
    const toggleEnrollment = document.getElementById("toggleEnrollment");
    const viewRegistrations = document.getElementById("viewRegistrations");
    const downloadData = document.getElementById("downloadData");
    const registrationsTable = document.getElementById("registrationsTable");
    const registrationsBody = document.getElementById("registrationsBody");

    // Backend base URL for production
    const backendBaseURL = "https://main-lpu-ncc.onrender.com"; // 🔁 actual backend URL

    // Fetch and set the current enrollment status
    async function loadEnrollmentStatus() {
        try {
          const response = await fetch(`${backendBaseURL}/api/enrollment`);
            const data = await response.json();
            toggleEnrollment.checked = data.enabled;
        } catch (error) {
            console.error("Error fetching enrollment status:", error);
        }
    }

    await loadEnrollmentStatus();

    // Toggle enrollment status
    toggleEnrollment.addEventListener("change", async function () {
        try {
          await fetch(`${backendBaseURL}/api/enrollment`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ enabled: toggleEnrollment.checked }),
            });
        } catch (error) {
            console.error("Error updating enrollment status:", error);
        }
    });

    // Load and display registrations
    async function loadRegistrations() {
        try {
          const response = await fetch(`${backendBaseURL}/api/registrations`);
            const data = await response.json();
            registrationsBody.innerHTML = "";

            if (data.length === 0) {
                alert("No registrations found.");
                registrationsTable.style.display = "none";
                return;
            }

            data.forEach((user) => {
                const row = document.createElement("tr");
                row.innerHTML = `
                    <td>${user.firstName} ${user.middleName ? user.middleName + " " : ""}${user.lastName}</td>
                    <td>${user.gender}</td>
                    <td>${user.regNumber}</td>
                    <td>${user.mobile}</td>
                    <td>${user.email}</td>
                    <td><button class="delete-btn" onclick="removeEntry('${user._id}')">Remove</button></td>
                `;
                registrationsBody.appendChild(row);
            });
            registrationsTable.style.display = "table";
        } catch (error) {
            console.error("Error fetching registrations:", error);
        }
    }

    viewRegistrations.addEventListener("click", loadRegistrations);

    // Delete a registration
    window.removeEntry = async function (id) {
        if (confirm("Are you sure you want to remove this entry?")) {
            try {
              const response = await fetch(`${backendBaseURL}/api/registrations/${id}`, {
                    method: "DELETE",
                });

                if (response.ok) {
                    loadRegistrations(); // Refresh the list after deletion
                } else {
                    console.error("Failed to delete registration.");
                }
            } catch (error) {
                console.error("Error deleting registration:", error);
            }
        }
    };

    // Download CSV
    downloadData.addEventListener("click", async function () {
        try {
          const response = await fetch(`${backendBaseURL}/api/registrations`);
            const data = await response.json();

            if (data.length === 0) {
                alert("No registrations to download.");
                return;
            }

            let csvContent = "Register ID,First Name,Middle Name,Last Name,Gender,Registration No,Mobile,Email\n";
            data.forEach(user => {
                csvContent += Object.values(user).map(value => `"${value}"`).join(",") + "\n";
            });

            let blob = new Blob([csvContent], { type: "text/csv" });
            let link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.download = "registrations.csv";
            link.click();
        } catch (error) {
            console.error("Error downloading CSV:", error);
        }
    });
});






  //news code
  const newsTableBody = document.getElementById("newsTableBody");

  // Fetch and display news on load
  fetch(`https://main-lpu-ncc.onrender.com/api/news`)
    .then(response => response.json())
    .then(newsItems => renderNews(newsItems))
    .catch(err => console.error('Error fetching news:', err));
  
  // Render the news items into the table
  function renderNews(newsItems) {
    newsTableBody.innerHTML = '';
    if (newsItems.length === 0) {
      newsTableBody.innerHTML = `<tr><td colspan="4" class="no-news">No news added yet.</td></tr>`;
      return;
    }
  
    newsItems.forEach(news => {
      const row = document.createElement("tr");
      const date = new Date(news.date).toLocaleDateString();
  
      const textCell = document.createElement("td");
      const urlCell = document.createElement("td");
      const dateCell = document.createElement("td");
      const actionCell = document.createElement("td");
  
      const textInput = document.createElement("input");
      textInput.value = news.text;
      textInput.type = "text";
      textInput.disabled = true;
  
      const urlInput = document.createElement("input");
      urlInput.value = news.url;
      urlInput.type = "text";
      urlInput.disabled = true;
  
      textCell.appendChild(textInput);
      urlCell.appendChild(urlInput);
      dateCell.textContent = date;
      actionCell.classList.add("actions");
  
      const editBtn = document.createElement("button");
      editBtn.textContent = "Edit";
  
      const saveBtn = document.createElement("button");
      saveBtn.textContent = "Save";
      saveBtn.style.display = "none";
  
      const deleteBtn = document.createElement("button");
      deleteBtn.textContent = "Delete";
      deleteBtn.classList.add("delete");
  
      editBtn.addEventListener("click", () => {
        textInput.disabled = false;
        urlInput.disabled = false;
        textInput.focus();
        editBtn.style.display = "none";
        saveBtn.style.display = "inline-block";
      });
  
      saveBtn.addEventListener("click", () => {
        const updatedText = textInput.value.trim();
        const updatedURL = urlInput.value.trim();
  
        fetch(`https://main-lpu-ncc.onrender.com/api/news/${news._id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: updatedText, url: updatedURL })
        })
        .then(response => response.json())
        .then(() => {
          textInput.disabled = true;
          urlInput.disabled = true;
          editBtn.style.display = "inline-block";
          saveBtn.style.display = "none";
          console.log("News updated successfully");
        })
        .catch(err => console.error("Error updating news:", err));
      });
  
      deleteBtn.addEventListener("click", () => deleteNews(news._id));
  
      actionCell.appendChild(editBtn);
      actionCell.appendChild(saveBtn);
      actionCell.appendChild(deleteBtn);
  
      row.appendChild(textCell);
      row.appendChild(urlCell);
      row.appendChild(dateCell);
      row.appendChild(actionCell);
  
      newsTableBody.appendChild(row);
    });
  }
  
  // Add new news item
function addNews() {
  const text = document.getElementById("newsText").value.trim();
  const url = document.getElementById("newsURL").value.trim();

  if (text && url) {
    fetch('https://main-lpu-ncc.onrender.com/api/news', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, url })
    })
    .then(response => response.json())
    .then(() => {
      fetch('https://main-lpu-ncc.onrender.com/api/news')
        .then(response => response.json())
        .then(newsItems => renderNews(newsItems));
      document.getElementById("newsText").value = '';
      document.getElementById("newsURL").value = '';
    })
    .catch(err => console.error('Error adding news:', err));
  }
}

  
  // Delete news item
  function deleteNews(id) {
    if (confirm("Delete this news item?")) {
      fetch(`https://main-lpu-ncc.onrender.com/api/news/${id}`, {
        method: 'DELETE'
      })
      .then(() => {
        fetch(`https://main-lpu-ncc.onrender.com/api/news`)
          .then(response => response.json())
          .then(newsItems => renderNews(newsItems));
      })
      .catch(err => console.error('Error deleting news:', err));
    }
  }

        // Toggle menu
        document.getElementById("menuToggle").addEventListener("click", function () {
            const menu = document.getElementById("menuOptions");
            menu.style.display = (menu.style.display === "none" || menu.style.display === "") ? "block" : "none";
        });

        // Logout
        function logout() {
            localStorage.removeItem("isAdminLoggedIn");
            window.location.href = "https://login-page-6jzv.onrender.com";
        }

// ======================================
// SHOW/HIDE PANELS
// ======================================

function showAlumniPanel(){

    document.getElementById(
        "mainAdminPanel"
    ).style.display = "none";

    document.getElementById(
        "sliderPanel"
    ).style.display = "none";

    document.getElementById(
        "classPanel"
    ).style.display = "none";

    document.getElementById(
        "alumniPanel"
    ).style.display = "block";

    // HIDE TOP BUTTONS

    document.getElementById(
        "topNavigationButtons"
    ).style.display = "none";

    loadAlumni();
}

function hideAlumniPanel(){

    document.getElementById(
        "mainAdminPanel"
    ).style.display = "block";

    document.getElementById(
        "alumniPanel"
    ).style.display = "none";

    // SHOW TOP BUTTONS AGAIN

    document.getElementById(
        "topNavigationButtons"
    ).style.display = "flex";
}


// ======================================
// ALUMNI API
// ======================================

const alumniBackend =
    "https://main-lpu-ncc.onrender.com";


// LOAD ALUMNI

async function loadAlumni(){

    try{

        const response =
            await fetch(
                `${alumniBackend}/api/alumni`
            );

        const data =
            await response.json();

        renderAlumni(data);

    }catch(error){

        console.error(error);
    }
}


// RENDER

function renderAlumni(data){

    const tableBody =
        document.getElementById(
            "alumniTableBody"
        );

    tableBody.innerHTML = "";

    data.forEach((alumni) => {

        tableBody.innerHTML += `

            <tr id="alumni-row-${alumni._id}">

                <!-- IMAGE -->

                <td>

                    <img 
                        src="${alumni.imageUrl}" 
                        id="preview-${alumni._id}"
                        style="
                            width:90px;
                            height:90px;
                            object-fit:cover;
                            border-radius:50%;
                            cursor:pointer;
                        "
                    >

                    <input
                        type="file"
                        id="image-${alumni._id}"
                        accept="image/*"
                        style="display:none;"
                        onchange="previewImage(event,'${alumni._id}')"
                    >

                </td>

                <!-- NAME -->

                <td>

                    <span id="name-text-${alumni._id}">
                        ${alumni.name}
                    </span>

                    <input
                        type="text"
                        id="name-${alumni._id}"
                        value="${alumni.name}"
                        style="display:none;"
                    >

                </td>

                <!-- FIELD -->

                <td>

                    <span id="field-text-${alumni._id}">
                        ${alumni.className}
                    </span>

                    <select
                        id="field-${alumni._id}"
                        style="display:none;"
                    >

                        <option value="INDIAN ARMY"
                        ${alumni.className === "INDIAN ARMY" ? "selected" : ""}>
                        INDIAN ARMY
                        </option>

                        <option value="INDIAN NAVY"
                        ${alumni.className === "INDIAN NAVY" ? "selected" : ""}>
                        INDIAN NAVY
                        </option>

                        <option value="INDIAN AIR FORCE"
                        ${alumni.className === "INDIAN AIR FORCE" ? "selected" : ""}>
                        INDIAN AIR FORCE
                        </option>

                    </select>

                </td>

                <!-- BATCH -->

                <td>

                    <span id="batch-text-${alumni._id}">
                        ${alumni.fromYear} - ${alumni.toYear}
                    </span>

                    <div
                        id="batch-inputs-${alumni._id}"
                        style="display:none;"
                    >

                        <input
                            type="number"
                            id="from-${alumni._id}"
                            value="${alumni.fromYear}"
                            style="width:80px;"
                        >

                        -

                        <input
                            type="number"
                            id="to-${alumni._id}"
                            value="${alumni.toYear}"
                            style="width:80px;"
                        >

                    </div>

                </td>

                <!-- ACTIONS -->

                <td>

                    <button
                        onclick="enableAlumniEdit('${alumni._id}')"
                        id="edit-btn-${alumni._id}"
                        style="
                            background:#ff9933;
                            color:white;
                        "
                    >

                        Edit

                    </button>

                    <button
                        onclick="updateAlumni('${alumni._id}')"
                        id="save-btn-${alumni._id}"
                        style="
                            display:none;
                            background:green;
                            color:white;
                        "
                    >

                        Save

                    </button>

                    <button
                        onclick="cancelAlumniEdit()"
                        id="cancel-btn-${alumni._id}"
                        style="
                            display:none;
                            background:#555;
                            color:white;
                        "
                    >

                        Cancel

                    </button>

                    <button
                        onclick='deleteAlumni("${alumni._id}")'
                        style="
                            background:red;
                            color:white;
                        "
                    >

                        Delete

                    </button>

                </td>

            </tr>
        `;
    });
}

function enableAlumniEdit(id){

    // SHOW INPUTS

    document.getElementById(
        `name-text-${id}`
    ).style.display = "none";

    document.getElementById(
        `field-text-${id}`
    ).style.display = "none";

    document.getElementById(
        `batch-text-${id}`
    ).style.display = "none";

    document.getElementById(
        `name-${id}`
    ).style.display = "inline-block";

    document.getElementById(
        `field-${id}`
    ).style.display = "inline-block";

    document.getElementById(
        `batch-inputs-${id}`
    ).style.display = "inline-block";

    // IMAGE CLICK ENABLE

    document.getElementById(
        `preview-${id}`
    ).onclick = () => {

        document.getElementById(
            `image-${id}`
        ).click();
    };

    // BUTTONS

    document.getElementById(
        `edit-btn-${id}`
    ).style.display = "none";

    document.getElementById(
        `save-btn-${id}`
    ).style.display = "inline-block";

    document.getElementById(
        `cancel-btn-${id}`
    ).style.display = "inline-block";
}

function cancelAlumniEdit(){

    loadAlumni();
}

async function updateAlumni(id){

    const formData = new FormData();

    formData.append(
    "name",
    toCaps(
            document.getElementById(`name-${id}`).value
        )
    );

    formData.append(
        "className",
        document.getElementById(`field-${id}`).value
    );

    formData.append(
        "fromYear",
        document.getElementById(`from-${id}`).value
    );

    formData.append(
        "toYear",
        document.getElementById(`to-${id}`).value
    );

    const imageFile =
        document.getElementById(`image-${id}`).files[0];

    if(imageFile){

        formData.append(
            "image",
            imageFile
        );
    }

    try{

        const response = await fetch(

            `${alumniBackend}/api/alumni/${id}`,

            {
                method:"PUT",
                body:formData
            }
        );

        const result = await response.json();

        alert(result.message);

        loadAlumni();

    }catch(error){

        console.error(error);
    }
}

// UPLOAD

async function uploadAlumni(){

    const name =
    toCaps(
        document.getElementById(
            "alumniName"
        ).value
    );

    const className =
        document.getElementById(
            "alumniField"
        ).value;

    const fromYear =
        document.getElementById(
            "fromYear"
        ).value;

    const toYear =
        document.getElementById(
            "toYear"
        ).value;

    const image =
        document.getElementById(
            "alumniImage"
        ).files[0];

    const formData =
        new FormData();

    formData.append("name", name);

    formData.append(
        "className",
        className
    );

    formData.append(
        "fromYear",
        fromYear
    );

    formData.append(
        "toYear",
        toYear
    );

    if(image){

        formData.append(
            "image",
            image
        );
    }

    try{

        const response =
            await fetch(

                `${alumniBackend}/api/alumni`,

                {
                    method:"POST",
                    body: formData
                }
            );

        const result =
            await response.json();

        alert(result.message);

        clearAlumniForm();

        loadAlumni();

    }catch(error){

        console.error(error);
    }
}



// DELETE

async function deleteAlumni(id){

    if(!confirm("Delete alumni?"))
        return;

    try{

        const response =
            await fetch(

                `${alumniBackend}/api/alumni/${id}`,

                {
                    method:"DELETE"
                }
            );

        const result =
            await response.json();

        alert(result.message);

        loadAlumni();

    }catch(error){

        console.error(error);
    }
}


// CLEAR FORM

function clearAlumniForm(){

    editingAlumniId = null;

    document.getElementById(
        "alumniName"
    ).value = "";

    document.getElementById(
        "alumniField"
    ).value = "";

    document.getElementById(
        "fromYear"
    ).value = "";

    document.getElementById(
        "toYear"
    ).value = "";

    document.getElementById(
        "alumniImage"
    ).value = "";
}

// ======================================
// FILTER ALUMNI TABLE
// ======================================

function filterAlumniTable(){

    const searchValue =
        document.getElementById(
            "alumniSearch"
        ).value.toLowerCase();

    const filterValue =
        document.getElementById(
            "alumniFilter"
        ).value.toLowerCase();

    const rows =
        document.querySelectorAll(
            "#alumniTableBody tr"
        );

    rows.forEach(row => {

        const name =
            row.querySelector(
                'input[id^="name-"]'
            ).value.toLowerCase();

        const field =
            row.querySelector(
                'select[id^="field-"]'
            ).value.toLowerCase();

        const matchSearch =
            name.includes(searchValue);

        const matchFilter =
            filterValue === "" ||
            field.includes(filterValue);

        row.style.display =
            (matchSearch && matchFilter)
            ? ""
            : "none";
    });
}

/* =========================================
   NCC PREMIUM UI EFFECTS
========================================= */

document.addEventListener("DOMContentLoaded", () => {

    /* =========================================
       HERO ANIMATION
    ========================================== */

    const hero = document.querySelector(".hero-section");

    if(hero){

        hero.style.opacity = "0";
        hero.style.transform = "translateY(30px)";

        setTimeout(() => {

            hero.style.transition = "1s ease";

            hero.style.opacity = "1";
            hero.style.transform = "translateY(0px)";

        }, 300);
    }

    /* =========================================
       BUTTON RIPPLE EFFECT
    ========================================== */

    const buttons = document.querySelectorAll("button");

    buttons.forEach(btn => {

        btn.addEventListener("mouseenter", () => {

            btn.style.transform =
                "translateY(-3px) scale(1.03)";
        });

        btn.addEventListener("mouseleave", () => {

            btn.style.transform =
                "translateY(0px) scale(1)";
        });

    });

    /* =========================================
       TABLE ROW HOVER GLOW
    ========================================== */

    const tables =
        document.querySelectorAll("table tbody tr");

    tables.forEach(row => {

        row.addEventListener("mouseenter", () => {

            row.style.transition = "0.3s ease";

            row.style.boxShadow =
                "0 0 20px rgba(255,255,255,0.15)";
        });

        row.addEventListener("mouseleave", () => {

            row.style.boxShadow = "none";
        });

    });

    /* =========================================
       LIVE CLOCK
    ========================================== */

    const clock =
        document.createElement("div");

    clock.id = "liveClock";

    clock.style.position = "fixed";
    clock.style.bottom = "20px";
    clock.style.right = "20px";
    clock.style.padding = "10px 18px";
    clock.style.borderRadius = "14px";
    clock.style.background = "rgba(0,0,0,0.5)";
    clock.style.backdropFilter = "blur(10px)";
    clock.style.color = "white";
    clock.style.fontWeight = "600";
    clock.style.zIndex = "9999";
    clock.style.boxShadow =
        "0 5px 20px rgba(0,0,0,0.3)";

    document.body.appendChild(clock);

    function updateClock(){

        const now = new Date();

        clock.innerHTML =
            "🕒 " +
            now.toLocaleTimeString();
    }

    updateClock();

    setInterval(updateClock, 1000);

    /* =========================================
       FLOATING PARTICLES
    ========================================== */

    const bg =
        document.querySelector(".bg-animation");

    if(bg){

        for(let i = 0; i < 15; i++){

            const particle =
                document.createElement("span");

            particle.style.position = "absolute";

            particle.style.width =
                Math.random() * 8 + 4 + "px";

            particle.style.height =
                particle.style.width;

            particle.style.background =
                "rgba(255,255,255,0.3)";

            particle.style.borderRadius = "50%";

            particle.style.left =
                Math.random() * 100 + "%";

            particle.style.top =
                Math.random() * 100 + "%";

            particle.style.animation =
                `floatParticle ${
                    Math.random() * 10 + 8
                }s linear infinite`;

            bg.appendChild(particle);
        }
    }

    /* =========================================
       PAGE LOADER EFFECT
    ========================================== */

    const loader =
        document.createElement("div");

    loader.innerHTML =
        "🇮🇳 Loading NCC Dashboard...";

    loader.style.position = "fixed";
    loader.style.inset = "0";
    loader.style.background =
        "linear-gradient(180deg,#ff9933,#ffffff,#138808)";
    loader.style.display = "flex";
    loader.style.justifyContent = "center";
    loader.style.alignItems = "center";
    loader.style.fontSize = "28px";
    loader.style.fontWeight = "700";
    loader.style.color = "#000";
    loader.style.zIndex = "999999";

    document.body.appendChild(loader);

    setTimeout(() => {

        loader.style.transition = "0.8s ease";
        loader.style.opacity = "0";

        setTimeout(() => {

            loader.remove();

        }, 800);

    }, 1200);

});

/* =========================================
   FLOATING PARTICLE ANIMATION STYLE
========================================= */

const particleStyle =
document.createElement("style");

particleStyle.innerHTML = `

@keyframes floatParticle{

    0%{
        transform:translateY(0px);
        opacity:0;
    }

    50%{
        opacity:1;
    }

    100%{
        transform:translateY(-120px);
        opacity:0;
    }
}

.hero-section{

    margin-top:20px;

    padding:50px 20px;

    border-radius:25px;

    background:
        rgba(255,255,255,0.08);

    backdrop-filter:blur(12px);

    box-shadow:
        0 10px 40px rgba(0,0,0,0.3);

    text-align:center;
}

.hero-subtitle{

    margin-top:15px;

    font-size:18px;

    color:#f5f5f5;
}

.footer{

    margin-top:40px;

    text-align:center;

    padding:20px;

    color:white;

    font-weight:500;

    opacity:0.9;
}

.bg-animation{

    position:fixed;

    inset:0;

    overflow:hidden;

    z-index:-1;
}

`;

document.head.appendChild(particleStyle);







// ======================================
// SHOW/HIDE SLIDER PANEL
// ======================================

function showSliderPanel(){

    document.getElementById(
        "mainAdminPanel"
    ).style.display = "none";

    document.getElementById(
        "alumniPanel"
    ).style.display = "none";

    document.getElementById(
        "classPanel"
    ).style.display = "none";

    document.getElementById(
        "sliderPanel"
    ).style.display = "block";

    document.getElementById(
        "topNavigationButtons"
    ).style.display = "none";

    loadSliderImages();
}

function hideSliderPanel(){

    document.getElementById(
        "mainAdminPanel"
    ).style.display = "block";

    document.getElementById(
        "sliderPanel"
    ).style.display = "none";

    document.getElementById(
        "topNavigationButtons"
    ).style.display = "flex";
}

// ======================================
// SLIDER API
// ======================================

const sliderBackend =
    "https://news-slider-tf3b.onrender.com";

// LOAD IMAGES

async function loadSliderImages(){

    try{

        const response =
            await fetch(
                `${sliderBackend}/images`
            );

        const data =
            await response.json();

        renderSliderImages(data);

    }catch(error){

        console.error(error);
    }
}

// RENDER IMAGES

function renderSliderImages(images){

    const container =
        document.getElementById(
            "sliderImagesContainer"
        );

    container.innerHTML = "";

    images.reverse().forEach(img => {

        container.innerHTML += `

            <div class="slider-image-card">

                <img src="${img.url}">

                <div class="slider-image-actions">

                    <button
                    class="slider-delete-btn"
                    onclick="deleteSliderImage('${img.id}')">

                        Delete Image

                    </button>

                </div>

            </div>
        `;
    });
}

// UPLOAD IMAGE

async function uploadSliderImage(){

    const image =
        document.getElementById(
            "sliderImage"
        ).files[0];

    if(!image){

        alert("Select image");

        return;
    }

    const formData =
        new FormData();

    formData.append(
        "image",
        image
    );

    try{

        const response =
            await fetch(

                `${sliderBackend}/upload`,

                {
                    method:"POST",
                    body:formData
                }
            );

        const result =
            await response.json();

        if(result.success){

            alert("Image uploaded");

            document.getElementById(
                "sliderImage"
            ).value = "";

            loadSliderImages();
        }

    }catch(error){

        console.error(error);
    }
}

// DELETE IMAGE

async function deleteSliderImage(id){

    if(!confirm("Delete image?"))
        return;

    try{

        const response =
            await fetch(

                `${sliderBackend}/delete/${id}`,

                {
                    method:"DELETE"
                }
            );

        const result =
            await response.json();

        if(result.success){

            loadSliderImages();
        }

    }catch(error){

        console.error(error);
    }
}

// ======================================
// CLASS PANEL
// ======================================

const classBackend =
    "https://camp-img-server.onrender.com";

let currentClass = "REPUBLIC DAY CAMP";

const placeInput =
document.getElementById("place");

const campInput =
document.getElementById("camp");

// SHOW PANEL

function showClassPanel(){

    document.getElementById(
        "mainAdminPanel"
    ).style.display = "none";

    document.getElementById(
        "alumniPanel"
    ).style.display = "none";

    document.getElementById(
        "sliderPanel"
    ).style.display = "none";

    document.getElementById(
        "classPanel"
    ).style.display = "block";

    document.getElementById(
        "topNavigationButtons"
    ).style.display = "none";

    loadClass("REPUBLIC DAY CAMP");
}

// HIDE PANEL

function hideClassPanel(){

    document.getElementById(
        "mainAdminPanel"
    ).style.display = "block";

    document.getElementById(
        "classPanel"
    ).style.display = "none";

    document.getElementById(
        "topNavigationButtons"
    ).style.display = "flex";
}

// LOAD CLASS

async function loadClass(className){

    currentClass = className;

    document.getElementById(
        "place"
    ).style.display = "none";

    document.getElementById(
        "camp"
    ).style.display = "none";

    if(className === "YOUTH EXCHANGE PROGRAM"){

        document.getElementById(
            "place"
        ).style.display = "block";
    }

    if(className === "RARE CAMPS"){

        document.getElementById(
            "camp"
        ).style.display = "block";
    }

    const response =
        await fetch(
            `${classBackend}/students`
        );

    const data =
        await response.json();

    renderStudents(
        data[className]
    );
}

async function addStudent(){

    const formData = new FormData();

    formData.append(
        "className",
        currentClass
    );

    formData.append(
        "name",
        toCaps(
            document.getElementById("name").value
        )
    );

    const fromBatch =
    document.getElementById(
        "fromBatch"
    ).value;

    const toBatch =
    document.getElementById(
        "toBatch"
    ).value;

    formData.append(
        "batch",
        `${fromBatch} - ${toBatch}`
    );

    formData.append(
        "rank",
        toCaps(
            document.getElementById("rank").value
        )
    );

    if(currentClass === "1D"){

        formData.append(
            "place",
            toCaps(
                document.getElementById("place").value
            )
        );
    }

    if(currentClass === "SPECIAL"){

        formData.append(
            "camp",
            toCaps(
                document.getElementById("camp").value
            )
        );
    }

    const image =
        document.getElementById("image").files[0];

    if(image){

        formData.append(
            "image",
            image
        );
    }

    try{

        const response =
            await fetch(

                `${classBackend}/add-student`,

                {
                    method:"POST",
                    body:formData
                }
            );

        const result =
            await response.json();

        alert(result.message);

        document.getElementById("name").value = "";

        document.getElementById("fromBatch").value = "";
        document.getElementById("toBatch").value = "";

        document.getElementById("rank").value = "";
        document.getElementById("place").value = "";
        document.getElementById("camp").value = "";
        document.getElementById("image").value = "";

        loadClass(currentClass);

    }catch(error){

        console.error(error);
    }
}

// RENDER STUDENTS

function renderStudents(students){

    const container =
        document.getElementById(
            "adminStudents"
        );

    container.innerHTML = "";

    students.forEach((student,index)=>{

        let extraField = "";

        if(currentClass === "YOUTH EXCHANGE PROGRAM"){

            extraField = `

            <div>

                <span id="place-text-${index}">
                    ${student.place || ""}
                </span>

                <input
                    type="text"
                    id="place-${index}"
                    value="${student.place || ""}"
                    style="display:none;"
                >

            </div>
            `;
        }

        if(currentClass === "RARE CAMPS"){

            extraField = `

            <div>

                <span id="camp-text-${index}">
                    ${student.camp || ""}
                </span>

                <input
                    type="text"
                    id="camp-${index}"
                    value="${student.camp || ""}"
                    style="display:none;"
                >

            </div>
            `;
        }

        const years =
            student.batch.includes("-")
            ? student.batch.split("-")
            : [student.batch, student.batch];

        container.innerHTML += `

            <div class="student-card">

                <img src="${student.image}">

                <div class="student-content">

                    <!-- NAME -->

                    <div>

                        <span id="name-text-${index}">
                            ${student.name}
                        </span>

                        <input
                            type="text"
                            id="name-${index}"
                            value="${student.name}"
                            style="display:none;"
                        >

                    </div>

                    <!-- BATCH -->

                    <div>

                        <span id="batch-text-${index}">
                            ${student.batch}
                        </span>

                        <div
                            id="batch-edit-${index}"
                            style="
                                display:none;
                                align-items:center;
                                gap:8px;
                            "
                        >

                            <input
                                type="number"
                                id="from-${index}"
                                value="${years[0].trim()}"
                            >

                            <span
                            style="
                                color:white;
                                font-weight:bold;
                            ">
                                -
                            </span>

                            <input
                                type="number"
                                id="to-${index}"
                                value="${years[1].trim()}"
                            >

                        </div>

                    </div>

                    <!-- RANK -->

                    <div>

                        <span id="rank-text-${index}">
                            ${student.rank}
                        </span>

                        <input
                            type="text"
                            id="rank-${index}"
                            value="${student.rank}"
                            style="display:none;"
                        >

                    </div>

                    ${extraField}

                    <!-- BUTTONS -->

                    <div class="admin-btns">

                        <button
                            onclick="enableEdit(${index}, '${student._id}')"
                            style="
                                background:#007bff;
                                color:white;
                            "
                        >

                            EDIT

                        </button>

                    </div>

                </div>

            </div>
        `;
    });
}

// ======================================
// ENABLE EDIT
// ======================================

function enableEdit(index,id){

    // HIDE TEXT

    document.getElementById(
        `name-text-${index}`
    ).style.display = "none";

    document.getElementById(
        `batch-text-${index}`
    ).style.display = "none";

    document.getElementById(
        `rank-text-${index}`
    ).style.display = "none";

    // SHOW INPUTS

    document.getElementById(
        `name-${index}`
    ).style.display = "block";

    document.getElementById(
        `rank-${index}`
    ).style.display = "block";

    document.getElementById(
        `batch-edit-${index}`
    ).style.display = "flex";

    // PLACE FIELD

    if(currentClass === "YOUTH EXCHANGE PROGRAM"){

        const placeText =
            document.getElementById(
                `place-text-${index}`
            );

        const placeInput =
            document.getElementById(
                `place-${index}`
            );

        if(placeText){

            placeText.style.display = "none";
        }

        if(placeInput){

            placeInput.style.display = "block";
        }
    }

    // CAMP FIELD

    if(currentClass === "RARE CAMPS"){

        const campText =
            document.getElementById(
                `camp-text-${index}`
            );

        const campInput =
            document.getElementById(
                `camp-${index}`
            );

        if(campText){

            campText.style.display = "none";
        }

        if(campInput){

            campInput.style.display = "block";
        }
    }

    // BUTTONS

    const buttons =
        document.querySelectorAll(
            `.student-card`
        )[index]
        .querySelector(".admin-btns");

    buttons.innerHTML = `

        <button
            onclick="updateStudent(${index}, '${id}')"
            style="
                background:green;
                color:white;
            "
        >

            UPDATE

        </button>

        <button
            onclick="deleteStudent('${id}')"
            style="
                background:red;
                color:white;
            "
        >

            DELETE

        </button>

        <button
            onclick="cancelEdit()"
            style="
                background:#555;
                color:white;
            "
        >

            CANCEL

        </button>

    `;
}

function cancelEdit(){

    loadClass(currentClass);
}

// ======================================
// UPDATE STUDENT
// ======================================

async function updateStudent(index,id){

    const formData = new FormData();

    formData.append(
        "name",
        toCaps(
            document.getElementById(
                `name-${index}`
            ).value
        )
    );

    const fromYear =
    document.getElementById(
        `from-${index}`
    ).value;

    const toYear =
    document.getElementById(
        `to-${index}`
    ).value;

    formData.append(
        "batch",
        `${fromYear} - ${toYear}`
    );

    formData.append(
        "rank",
        toCaps(
            document.getElementById(
                `rank-${index}`
            ).value
        )
    );

    if(currentClass === "1D"){

        formData.append(
            "place",
            toCaps(
                document.getElementById(
                `place-${index}`
            ).value
        )
    );
    }

    if(currentClass === "SPECIAL"){

        formData.append(
            "camp",
            toCaps(
            document.getElementById(
                `camp-${index}`
            ).value
        )
    );
    }

    const res = await fetch(

        `${classBackend}/edit-student/${id}`,

        {
            method:"PUT",
            body:formData
        }

    );

    const data = await res.json();

    alert(data.message);

    loadClass(currentClass);
}

// ======================================
// FORMAT BATCH YEAR
// ======================================

function formatBatch(batch){

    batch = batch.trim();

    if(batch.includes("-")){

        const years =
            batch.split("-");

        if(years.length === 2){

            return `${years[0].trim()} - ${years[1].trim()}`;
        }
    }

    return batch;
}

// ======================================
// DELETE STUDENT
// ======================================

async function deleteStudent(id){

    if(!confirm("Delete student?"))
        return;

    try{

        const response =
            await fetch(

                `${classBackend}/delete-student/${id}`,

                {
                    method:"DELETE"
                }
            );

        const data =
            await response.json();

        alert(data.message);

        loadClass(currentClass);

    }catch(error){

        console.error(error);
    }
}
