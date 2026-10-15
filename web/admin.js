(function () {
  "use strict";
  document.addEventListener("click", function (event) {
    var button = event.target.closest("button.copy");
    if (!button) return;
    var section = button.closest(".secret");
    var source = section && section.querySelector("pre");
    if (!source) return;
    var text = source.textContent || "";
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () {
        button.textContent = "已复制";
      }).catch(function () { fallbackCopy(text, button); });
    } else {
      fallbackCopy(text, button);
    }
  });
  function fallbackCopy(text, button) {
    var field = document.createElement("textarea");
    field.value = text;
    field.className = "copy-fallback";
    field.setAttribute("readonly", "");
    document.body.appendChild(field);
    field.select();
    try {
      if (document.execCommand("copy")) button.textContent = "已复制";
    } finally {
      field.remove();
    }
  }
  function updateCount() {
    var checks = Array.prototype.slice.call(document.querySelectorAll("input[type=checkbox][name=secret]"));
    var count = checks.filter(function (input) { return input.checked; }).length;
    document.querySelectorAll(".selected-count").forEach(function (node) {
      node.textContent = String(count);
    });
    document.querySelectorAll("button.selected-submit").forEach(function (button) {
      button.textContent = "生成项目配置（已选 " + count + "）";
    });
  }
  document.addEventListener("change", function (event) {
    if (event.target.matches("input[type=checkbox][name=secret]")) updateCount();
  });
  updateCount();
}());
