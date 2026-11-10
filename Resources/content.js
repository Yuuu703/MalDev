function copyCode(button) {
  let container = button.parentElement;
  while (container && !container.querySelector("pre code")) container = container.parentElement;
  const code = container?.querySelector("pre code")?.textContent;
  if (!code) return;
  const fallback = () => {
    const textarea = document.createElement("textarea");
    textarea.value = code;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  };
  if (navigator.clipboard?.writeText) navigator.clipboard.writeText(code).catch(fallback);
  else fallback();
  const label = button.querySelector("span");
  if (label) {
    const old = label.textContent;
    label.textContent = "Copied";
    setTimeout(() => { label.textContent = old; }, 900);
  }
}

function openImageModal(src) {
  window.open(src, "_blank", "noopener");
}
