(() => {
  const page = document.getElementById("analyze-page");
  if (!page) return;

  const targetUrl = page.dataset.url;
  const steps = Array.from(document.querySelectorAll(".live-step"));
  const rules = Array.from(document.querySelectorAll("#live-rules .rule-tick"));
  const statusEl = document.getElementById("analyze-status");
  const hintEl = document.getElementById("live-hint");
  const errorEl = document.getElementById("live-error");
  const rulesProgress = document.getElementById("rules-progress");

  let stepIndex = 0;
  let ruleIndex = 0;
  let stepTimer = null;
  let ruleTimer = null;
  let finished = false;

  function setStepState(index, state) {
    steps.forEach((el, i) => {
      el.classList.remove("is-active", "is-done");
      if (i < index) el.classList.add("is-done");
      if (i === index && state === "active") el.classList.add("is-active");
      if (i === index && state === "done") el.classList.add("is-done");
      const mark = el.querySelector(".live-step-mark");
      if (!mark) return;
      if (i < index || (i === index && state === "done")) mark.textContent = "✓";
      else if (i === index) mark.textContent = "…";
      else mark.textContent = "";
    });
  }

  function pulseRules() {
    if (finished || !rules.length) return;
    const el = rules[ruleIndex % rules.length];
    rules.forEach((r) => r.classList.remove("is-checking"));
    el.classList.remove("is-pending");
    el.classList.add("is-checking");
    const mark = el.querySelector(".tick-mark");
    if (mark) mark.textContent = "…";
    ruleIndex += 1;
    if (rulesProgress) {
      const checked = Math.min(ruleIndex, rules.length);
      rulesProgress.textContent = `Đang kiểm tra ${checked}/${rules.length}…`;
    }
  }

  function startAnimations() {
    setStepState(0, "active");
    stepTimer = window.setInterval(() => {
      if (finished) return;
      stepIndex = Math.min(stepIndex + 1, steps.length - 1);
      setStepState(stepIndex, "active");
      if (stepIndex >= steps.length - 1 && stepTimer) {
        window.clearInterval(stepTimer);
        stepTimer = null;
      }
    }, 700);

    pulseRules();
    ruleTimer = window.setInterval(pulseRules, 550);
  }

  function stopAnimations() {
    finished = true;
    if (stepTimer) window.clearInterval(stepTimer);
    if (ruleTimer) window.clearInterval(ruleTimer);
    setStepState(steps.length - 1, "done");
    steps.forEach((el) => {
      el.classList.add("is-done");
      el.classList.remove("is-active");
      const mark = el.querySelector(".live-step-mark");
      if (mark) mark.textContent = "✓";
    });
  }

  function showError(message) {
    stopAnimations();
    if (statusEl) statusEl.textContent = "Thất bại";
    if (hintEl) hintEl.hidden = true;
    if (errorEl) {
      errorEl.hidden = false;
      errorEl.textContent = message;
    }
    if (rulesProgress) rulesProgress.textContent = "Không hoàn tất";
  }

  async function runScan() {
    startAnimations();
    try {
      const res = await fetch("/api/v1/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ url: targetUrl }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = data.detail || data.message || `Lỗi HTTP ${res.status}`;
        showError(typeof detail === "string" ? detail : JSON.stringify(detail));
        return;
      }
      stopAnimations();
      if (statusEl) statusEl.textContent = "Hoàn tất — đang mở báo cáo…";
      if (rulesProgress) rulesProgress.textContent = "Xong — chuyển trang kết quả";
      window.location.replace(`/scans/${data.id}`);
    } catch (err) {
      showError(err && err.message ? err.message : "Không gọi được API phân tích.");
    }
  }

  runScan();
})();
