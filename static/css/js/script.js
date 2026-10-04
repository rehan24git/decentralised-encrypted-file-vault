const fileInput = document.getElementById("fileInput");
const uploadSubmit = document.getElementById("uploadSubmit");

if (fileInput && uploadSubmit) {

    fileInput.addEventListener("change", function () {

        if (fileInput.files.length > 0) {

            uploadSubmit.style.display = "inline-block";
            uploadSubmit.textContent = "Encrypt & Save";

        } else {

            uploadSubmit.style.display = "none";

        }

    });

}