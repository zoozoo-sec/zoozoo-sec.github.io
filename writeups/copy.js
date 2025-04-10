
document.querySelectorAll(".copy-btn").forEach(function(btn) {
    btn.addEventListener("click", function() {
        // find the parent .section-content
        const section = btn.closest(".section-content");
        // find the code block within it
        const code = section.querySelector("pre > code");
        if (code) {
            const text = code.innerText;
            navigator.clipboard.writeText(text).then(function() {
                btn.textContent = "Copied!";
                setTimeout(() => (btn.textContent = "Copy"), 1000);
            }).catch(function(err) {
                alert("Failed to copy text: " + err);
            });
        }
    });
});
