(() => {
  const form = document.getElementById("scan-form");
  if (!form) return;

  const urlInput = document.getElementById("url");
  const submitBtn = document.getElementById("scan-submit");

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }
    const value = (urlInput && urlInput.value.trim()) || "";
    if (!value) return;
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = "Chuyển trang…";
    }
    // Nhảy ngay sang trang kết quả (UI đang phân tích), không chờ modal
    window.location.href = `/analyze?url=${encodeURIComponent(value)}`;
  });
})();
