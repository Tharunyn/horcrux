
(function () {
  "use strict";

  const params = new URLSearchParams(window.location.search);
  const TOKEN = params.get("token") || "";

  const tokenState = document.getElementById("tokenState");
  if (TOKEN) {
    tokenState.textContent = "token loaded";
  } else {
    tokenState.textContent = "no token in URL — every action will 401";
    tokenState.classList.add("is-bad");
  }

  async function api(path, options) {
    options = options || {};
    const headers = Object.assign(
      { "Content-Type": "application/json", "X-Horcrux-Token": TOKEN },
      options.headers || {}
    );

    const res = await fetch("/api" + path, {
      method: options.method || "GET",
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    let data = null;

    try {
      data = await res.json();
    } catch (e) {
      data = null;
    }

    if (!res.ok) {
      const err = new Error((data && data.error) || res.statusText);
      err.status = res.status;
      err.data = data;
      throw err;
    }

    return data;
  }

  function el(tag, attrs, children) {
    const node = document.createElement(tag);

    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === "class") {
        node.className = v;
      } else if (k === "html") {
        node.innerHTML = v;
      } else if (v !== false && v !== null && v !== undefined) {
        node.setAttribute(k, v === true ? "" : String(v));
      }
    });

    (children || []).forEach((c) =>
      node.appendChild(
        typeof c === "string" ? document.createTextNode(c) : c
      )
    );

    return node;
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function banner(kind, title, reasons) {
    const b = el("div", { class: "banner banner-" + kind }, [title]);

    if (reasons && reasons.length) {
      const ul = el(
        "ul",
        {},
        reasons.map((r) => el("li", {}, [String(r)]))
      );

      b.appendChild(ul);
    }

    return b;
  }

  function kvTable(rows) {
    const table = el("table", { class: "kv" });

    rows.forEach(([k, v]) => {
      if (v === undefined || v === null) return;

      table.appendChild(
        el("tr", {}, [
          el("td", {}, [k]),
          el("td", {}, [v instanceof Node ? v : String(v)]),
        ])
      );
    });

    return table;
  }

  function copyable(text) {
    const wrap = el("span", { class: "copyable" }, [text]);
    const btn = el("button", { class: "copy-inline", type: "button" }, ["copy"]);

    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = "copied";
        setTimeout(() => (btn.textContent = "copy"), 1200);
      } catch (e) {}
    });

    wrap.appendChild(btn);
    return wrap;
  }

  // ============================================================
  // SECTION SWITCHING
  // ============================================================

  const railItems = document.querySelectorAll(".rail-item");
  const sections = document.querySelectorAll("[data-section]");

  railItems.forEach((btn) => {
    btn.addEventListener("click", () => {
      railItems.forEach((b) => b.classList.remove("is-active"));
      btn.classList.add("is-active");

      const target = btn.dataset.section;

      sections.forEach((s) => {
        s.hidden = s.id !== "section-" + target;
      });

      if (target === "log") {
        loadLog();
        loadRiskAssessment();
      }
    });
  });

  // ============================================================
  // ACCESS LOG
  // ============================================================

  function kindBadge(kind) {
    const map = {
      decrypt_ok: "ok",
      decrypt_fail: "fail",
      blocked: "blocked",
      signed: "signed",
    };

    return el("span", { class: "badge badge-" + (map[kind] || "ok") }, [
      kind,
    ]);
  }

  async function loadLog() {
    const result = document.getElementById("logResult");

    clear(result);
    result.appendChild(el("p", {}, ["Loading…"]));

    try {
      const tailInput = document.getElementById("logTail").value;
      const q = tailInput ? "?tail=" + encodeURIComponent(tailInput) : "";
      const data = await api("/log" + q);

      clear(result);

      if (!data.entries.length) {
        result.appendChild(el("p", {}, ["No access log entries yet."]));
        return;
      }

      const table = el("table", { class: "data" });

      table.appendChild(
        el(
          "tr",
          {},
          ["Time (UTC)", "Attempt", "Shard", "Kind"].map((h) =>
            el("th", {}, [h])
          )
        )
      );

      data.entries
        .slice()
        .reverse()
        .forEach((entry) => {
          table.appendChild(
            el("tr", {}, [
              el("td", {}, [entry.ts_utc]),
              el("td", {}, [String(entry.attempt)]),
              el("td", {}, [
                entry.shard_id ? String(entry.shard_id) : "—",
              ]),
              el("td", {}, [kindBadge(entry.kind)]),
            ])
          );
        });

      result.appendChild(table);
    } catch (e) {
      clear(result);
      result.appendChild(banner("error", e.message));
    }
  }

  document.getElementById("logReload").addEventListener("click", () => {
    loadLog();
    loadRiskAssessment();
  });

  // ============================================================
  // RISK ASSESSMENT
  // ============================================================

  async function loadRiskAssessment() {
    const result = document.getElementById("riskResult");
    const reloadButton = document.getElementById("riskReload");

    clear(result);
    result.appendChild(el("p", {}, ["Analysing access-log activity…"]));

    if (reloadButton) reloadButton.disabled = true;

    try {
      const assessment = await api("/risk-assessment");

      clear(result);

      const level = String(assessment.level || "unknown").toLowerCase();
      const levelClass = ["low", "medium", "high"].includes(level)
        ? level
        : "unknown";

      const score = Number(assessment.score);
      const metrics = assessment.metrics || {};

      result.appendChild(
        el("div", { class: "risk-summary risk-" + levelClass }, [
          el("div", { class: "risk-level" }, [
            String(assessment.level || "Unknown").toUpperCase() + " RISK",
          ]),
          el("div", { class: "risk-score" }, [
            Number.isFinite(score) ? score + " / 100" : "Score unavailable",
          ]),
        ])
      );

      result.appendChild(el("h3", {}, ["Why this risk level?"]));

      const reasons = Array.isArray(assessment.reasons)
        ? assessment.reasons
        : [];

      if (reasons.length) {
        result.appendChild(
          el(
            "ul",
            { class: "risk-list" },
            reasons.map((reason) => el("li", {}, [String(reason)]))
          )
        );
      } else {
        result.appendChild(
          el("p", {}, ["No specific risk indicators reported."])
        );
      }

      result.appendChild(el("h3", {}, ["Recommended actions"]));

      const recommendations = Array.isArray(assessment.recommendations)
        ? assessment.recommendations
        : [];

      if (recommendations.length) {
        result.appendChild(
          el(
            "ul",
            { class: "risk-list" },
            recommendations.map((item) => el("li", {}, [String(item)]))
          )
        );
      } else {
        result.appendChild(
          el("p", {}, ["No recommendations available."])
        );
      }

      result.appendChild(el("h3", {}, ["Activity metrics"]));

      result.appendChild(
        kvTable([
          ["Entries analysed", metrics.entries_analyzed],
          ["Entries in one-hour window", metrics.entries_in_window],
          ["Failed decryptions", metrics.failed_decryptions],
          ["Failed attempts", metrics.failed_attempts],
          ["Blocked attempts", metrics.blocked_attempts],
          ["Attempts in window", metrics.attempts_in_window],
          ["Rapid attempts", metrics.rapid_attempts],
          ["Affected shards", metrics.affected_shards],
          ["Events between 00:00–06:00 UTC", metrics.odd_hour_events],
        ])
      );

      result.appendChild(
        el("p", { class: "risk-disclaimer" }, [
          "This assessment is advisory. It does not independently block or authorize signing operations.",
        ])
      );
    } catch (e) {
      clear(result);
      result.appendChild(
        banner("error", "Risk assessment failed: " + e.message)
      );
    } finally {
      if (reloadButton) reloadButton.disabled = false;
    }
  }

  document
    .getElementById("riskReload")
    .addEventListener("click", loadRiskAssessment);

  loadLog();
  loadRiskAssessment();

  // ============================================================
  // SHARED FORM HELPERS
  // ============================================================

  function lines(value) {
    return value
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function setBusy(form, busy) {
    form.querySelectorAll("button[type=submit]").forEach((b) => {
      b.disabled = busy;
    });
  }

  function formData(form) {
    const fd = new FormData(form);
    const out = {};

    for (const [k, v] of fd.entries()) {
      out[k] = v;
    }

    form.querySelectorAll('input[type=checkbox]').forEach((cb) => {
      out[cb.name] = cb.checked;
    });

    return out;
  }

  function clearPasswordValues(container) {
    if (!container) return;

    container.querySelectorAll('input[type="password"]').forEach((input) => {
      input.value = "";
    });
  }

  function passwordInputs(container) {
    return Array.from(
      container.querySelectorAll('input[type="password"]')
    );
  }

  function validCount(value, minimum) {
    const n = Number(value);

    return Number.isInteger(n) && n >= minimum && n <= 255 ? n : 0;
  }

  function renderPasswordFields(container, count, label, requiredCount) {
    clear(container);

    if (!count) {
      container.appendChild(
        el("p", { class: "password-hint" }, [
          "Enter a valid number of shares to create password fields.",
        ])
      );
      return;
    }

    for (let i = 0; i < count; i++) {
      const input = el("input", {
        type: "password",
        autocomplete: "new-password",
        "aria-label": label + " " + (i + 1),
      });

      input.dataset.passwordIndex = String(i);
      input.required = i < requiredCount;

      const field = el("label", { class: "field password-entry" }, [
        el("span", {}, [
          label + " " + (i + 1) +
          (i < requiredCount ? " (required)" : " (optional)"),
        ]),
        input,
      ]);

      container.appendChild(field);
    }
  }

  function deviceOptions(devices) {
    if (Array.isArray(devices) && devices.length > 0) {
      return devices;
    }

    return [{
      id: "local",
      label: "This computer",
      kind: "computer",
      root: "",
    }];
  }

  let cachedDevices = null;

  async function fetchDevices() {
    try {
      const res = await api("/devices");
      if (Array.isArray(res.devices) && res.devices.length > 0) {
        return res.devices;
      }
    } catch (e) {
      // Fall back to a local-only selector if enumeration is unavailable.
    }

    return deviceOptions(null);
  }

  async function ensureDevices() {
    if (!cachedDevices) {
      cachedDevices = await fetchDevices();
    }
    return cachedDevices;
  }

  function deviceValue(device) {
    return device.kind === "computer" ? "" : device.root || "";
  }

  function renderSplitPasswordFields(container, count, label, devices) {
    clear(container);

    if (!count) {
      container.appendChild(
        el("p", { class: "password-hint" }, [
          "Enter a valid number of shares to choose destinations and passwords.",
        ])
      );
      return;
    }

    const options = deviceOptions(devices);

    for (let i = 0; i < count; i++) {
      const device = options[i % options.length];
      const input = el("input", {
        type: "password",
        autocomplete: "new-password",
        "aria-label": label + " " + (i + 1),
      });

      input.dataset.passwordIndex = String(i);
      input.required = true;

      const select = el("select", { class: "device-select" });

      options.forEach((option, optionIndex) => {
        select.appendChild(
          el("option", {
            value: deviceValue(option),
            title: option.root || "",
          }, [option.label])
        );

        if (optionIndex === i % options.length) {
          select.value = deviceValue(option);
        }
      });

      const entry = el("div", { class: "password-entry split-entry" });
      const destinationLabel = el("span", { class: "password-entry-path" }, [
        device && device.label ? "→ " + device.label : "→ select a device",
      ]);

      entry.appendChild(
        el("div", { class: "password-entry-head" }, [
          el("span", { class: "password-entry-title" }, [
            label + " " + (i + 1) + " (required)",
          ]),
          destinationLabel,
        ])
      );

      select.addEventListener("change", () => {
        const chosen = options.find(
          (option) => deviceValue(option) === select.value
        );
        destinationLabel.textContent = chosen
          ? "→ " + chosen.label
          : "→ select a device";
      });

      entry.appendChild(
        el("label", { class: "field device-field" }, [
          el("span", {}, ["Destination device"]),
          select,
        ])
      );

      entry.appendChild(
        el("label", { class: "field password-field" }, [
          el("span", {}, ["Password"]),
          input,
        ])
      );

      container.appendChild(entry);
    }
  }

  function getSplitSelection(container, expected) {
    const inputs = passwordInputs(container);

    if (inputs.length !== expected) {
      throw new Error(
        "Password fields do not match the number of shards/shares. Please check the share count."
      );
    }

    const passwords = inputs.map((input) => input.value);

    if (passwords.some((password) => password.length === 0)) {
      throw new Error(
        "Enter a separate password for every generated shard/share."
      );
    }

    const devices = inputs.map((input) => {
      const entry = input.closest(".split-entry");
      const select = entry ? entry.querySelector(".device-select") : null;
      return select ? select.value : "";
    });

    return { passwords, devices };
  }

  function renderSigningPasswordFields(
    container,
    paths,
    label,
    requiredCount,
    devices
  ) {
    clear(container);

    const options = deviceOptions(devices);

    paths.forEach((path, i) => {
      const input = el("input", {
        type: "password",
        autocomplete: "current-password",
        "aria-label": label + " " + (i + 1),
      });

      input.dataset.passwordIndex = String(i);
      input.dataset.filePath = path;
      input.required = i < requiredCount;

      const entry = el("div", { class: "password-entry signing-entry" });

      entry.appendChild(
        el("div", { class: "password-entry-head" }, [
          el("span", { class: "password-entry-title" }, [
            label + " " + (i + 1) +
            (i < requiredCount ? " (required)" : " (optional)"),
          ]),
          el("span", { class: "password-entry-path" }, [path]),
        ])
      );

      const select = el("select", { class: "device-select" });

      options.forEach((device) => {
        select.appendChild(
          el("option", {
            value: device.id,
            title: device.root || "",
          }, [device.label])
        );
      });

      entry.appendChild(
        el("label", { class: "device-field" }, [
          el("span", {}, ["Device"]),
          select,
        ])
      );

      entry.appendChild(
        el("label", { class: "field password-field" }, [
          el("span", {}, ["Password"]),
          input,
        ])
      );

      container.appendChild(entry);
    });
  }

  function getAllPasswordValues(container, expected) {
    const inputs = passwordInputs(container);

    if (inputs.length !== expected) {
      throw new Error(
        "Password fields do not match the number of shares. Please check the share count."
      );
    }

    const passwords = inputs.map((input) => input.value);

    if (passwords.some((password) => password.length === 0)) {
      throw new Error(
        "Enter a separate password for every generated shard/share."
      );
    }

    return passwords;
  }

  function getSigningSelection(container, expected, threshold) {
    const inputs = passwordInputs(container);

    if (inputs.length !== expected) {
      throw new Error(
        "Password fields do not match the selected files. Check the file list."
      );
    }

    const selectedPaths = [];
    const selectedPasswords = [];

    inputs.forEach((input) => {
      if (input.value.length > 0) {
        selectedPaths.push(input.dataset.filePath);
        selectedPasswords.push(input.value);
      }
    });

    if (selectedPaths.length < threshold) {
      throw new Error(
        "The threshold is " + threshold +
        ". Enter passwords for at least " + threshold +
        " selected shares/shards. You entered " + selectedPaths.length + "."
      );
    }

    if (selectedPaths.some((path) => !path)) {
      throw new Error(
        "A selected file could not be matched to its password. Re-enter the file paths."
      );
    }

    return {
      paths: selectedPaths,
      passwords: selectedPasswords,
    };
  }

  async function handleBlocked(err, form, result) {
    clear(result);

    if (err.status === 409 && err.data && err.data.reasons) {
      result.appendChild(
        banner("error", "Audit blocked this attempt:", err.data.reasons)
      );

      const forceField = form.querySelector(".force-field");

      if (forceField) {
        forceField.hidden = false;
        forceField.querySelector("input").checked = true;
      }

      result.appendChild(
        el("p", {}, [
          "Review the audit warning. If you retry, enter the passwords again.",
        ])
      );
    } else {
      result.appendChild(banner("error", err.message));
    }
  }

  // ============================================================
  // DYNAMIC SPLIT PASSWORD FIELDS
  // ============================================================

  const initSharesInput = document.getElementById("initShares");
  const initPasswordFields = document.getElementById("initPasswordFields");

  const mpcSharesInput = document.getElementById("mpcShares");
  const mpcSplitPasswordFields = document.getElementById(
    "mpcSplitPasswordFields"
  );

  let initSplitVersion = 0;
  let mpcSplitVersion = 0;

  async function updateInitPasswordFields() {
    const count = validCount(initSharesInput.value, 1);
    const version = ++initSplitVersion;
    const devices = await ensureDevices();

    if (version !== initSplitVersion) return;

    renderSplitPasswordFields(
      initPasswordFields,
      count,
      "Shard",
      devices
    );
  }

  async function updateMpcSplitPasswordFields() {
    const count = validCount(mpcSharesInput.value, 2);
    const version = ++mpcSplitVersion;
    const devices = await ensureDevices();

    if (version !== mpcSplitVersion) return;

    renderSplitPasswordFields(
      mpcSplitPasswordFields,
      count,
      "Share",
      devices
    );
  }

  initSharesInput.addEventListener("input", updateInitPasswordFields);
  mpcSharesInput.addEventListener("input", updateMpcSplitPasswordFields);

  updateInitPasswordFields();
  updateMpcSplitPasswordFields();

  // ============================================================
  // SIGNING PASSWORD FIELDS
  // Discover the threshold from the selected files through /verify.
  // ============================================================

  const signShardPaths = document.getElementById("signShardPaths");
  const signPasswordFields = document.getElementById("signPasswordFields");

  const mpcSignSharePaths = document.getElementById("mpcSignSharePaths");
  const mpcSignPasswordFields = document.getElementById(
    "mpcSignPasswordFields"
  );

  const reconstructShardPaths = document.getElementById(
    "reconstructShardPaths"
  );
  const reconstructPasswordFields = document.getElementById(
    "reconstructPasswordFields"
  );

  let signRefreshVersion = 0;
  let mpcSignRefreshVersion = 0;

  function showPasswordStatus(container, message, kind) {
    clear(container);

    const status = el("p", {
      class: "password-hint" + (kind ? " " + kind : ""),
    }, [message]);

    container.appendChild(status);
  }

  async function updateSigningPasswordFields(
    pathInput,
    container,
    label,
    versionType
  ) {
    const paths = lines(pathInput.value);
    const version = ++versionType.current;

    if (paths.length === 0) {
      showPasswordStatus(
        container,
        "Enter the selected file paths to discover the threshold."
      );
      return;
    }

    showPasswordStatus(
      container,
      "Checking selected files to discover the threshold..."
    );

    try {
      const [verification, devices] = await Promise.all([
        api("/verify", {
          method: "POST",
          body: {
            files: paths,
            password: null,
          },
        }),
        fetchDevices(),
      ]);

      if (version !== versionType.current) return;

      if (
        !Array.isArray(verification.reports) ||
        verification.reports.length !== paths.length
      ) {
        throw new Error("Could not read verification information for every file.");
      }

      const thresholds = verification.reports.map((report) =>
        Number(report.threshold)
      );

      const kinds = verification.reports.map((report) => report.kind);

      if (
        thresholds.some(
          (threshold) =>
            !Number.isInteger(threshold) ||
            threshold < 1 ||
            threshold > 255
        )
      ) {
        throw new Error(
          "The threshold could not be read from the selected files. Check that the files are valid."
        );
      }

      if (thresholds.some((threshold) => threshold !== thresholds[0])) {
        throw new Error(
          "The selected files have different thresholds. Select files from the same split."
        );
      }

      if (kinds.some((kind) => kind !== kinds[0])) {
        throw new Error(
          "The selected files belong to different share types. Do not mix SSS and FROST files."
        );
      }

      if (paths.length < thresholds[0]) {
        throw new Error(
          "This set requires at least " + thresholds[0] +
          " files, but only " + paths.length + " were selected."
        );
      }

      const threshold = thresholds[0];

      renderSigningPasswordFields(
        container,
        paths,
        label,
        threshold,
        devices
      );

      const inputs = passwordInputs(container);

      inputs.forEach((input, index) => {
        input.dataset.filePath = paths[index];
      });

      container.appendChild(
        el("p", { class: "password-hint" }, [
          "Threshold: " + threshold + " of " + paths.length +
          ". The first " + threshold +
          " passwords are required. Additional passwords are optional.",
        ])
      );
    } catch (e) {
      if (version !== versionType.current) return;

      showPasswordStatus(
        container,
        "Could not determine threshold: " + e.message,
        "is-error"
      );
    }
  }

  const signVersion = { current: 0 };
  const mpcSignVersion = { current: 0 };
  const reconstructVersion = { current: 0 };

  function refreshSignPasswordFields() {
    updateSigningPasswordFields(
      signShardPaths,
      signPasswordFields,
      "Shard password",
      signVersion
    );
  }

  function refreshMpcSignPasswordFields() {
    updateSigningPasswordFields(
      mpcSignSharePaths,
      mpcSignPasswordFields,
      "Share password",
      mpcSignVersion
    );
  }

  function refreshReconstructPasswordFields() {
    updateSigningPasswordFields(
      reconstructShardPaths,
      reconstructPasswordFields,
      "Shard password",
      reconstructVersion
    );
  }

  signShardPaths.addEventListener("input", refreshSignPasswordFields);
  mpcSignSharePaths.addEventListener("input", refreshMpcSignPasswordFields);
  reconstructShardPaths.addEventListener(
    "input",
    refreshReconstructPasswordFields
  );

  refreshSignPasswordFields();
  refreshMpcSignPasswordFields();
  refreshReconstructPasswordFields();

  // ============================================================
  // VERIFY
  // ============================================================

  const verifyForm = document.getElementById("verifyForm");

  verifyForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();

    const result = document.getElementById("verifyResult");
    const data = formData(verifyForm);

    setBusy(verifyForm, true);
    clear(result);

    try {
      const res = await api("/verify", {
        method: "POST",
        body: {
          files: lines(data.files),
          password: data.password || null,
        },
      });

      clear(result);

      if (res.consistency_error) {
        result.appendChild(
          banner("error", "Inconsistent set: " + res.consistency_error)
        );
      } else {
        result.appendChild(
          banner(
            res.all_ok ? "ok" : "error",
            res.all_ok
              ? "All files verified."
              : "Verification failed for one or more files."
          )
        );
      }

      const table = el("table", { class: "data" });

      table.appendChild(
        el(
          "tr",
          {},
          ["Path", "Kind", "t / n", "Status"].map((h) =>
            el("th", {}, [h])
          )
        )
      );

      res.reports.forEach((r) => {
        table.appendChild(
          el("tr", {}, [
            el("td", {}, [r.path]),
            el("td", {}, [r.kind ? r.kind.toUpperCase() : "invalid"]),
            el("td", {}, [
              r.threshold != null
                ? r.threshold + " / " + r.shares
                : "—",
            ]),
            el("td", {}, [
              r.ok
                ? el("span", { class: "badge badge-ok" }, ["ok"])
                : el("span", { class: "badge badge-fail" }, ["fail"]),
            ]),
          ])
        );
      });

      result.appendChild(table);
    } catch (e) {
      clear(result);
      result.appendChild(banner("error", e.message));
    } finally {
      setBusy(verifyForm, false);
    }
  });
  function qrShowButton(path) {
    const wrap = el("div", { class: "qr-show-wrap" });
    const button = el("button", {
      class: "btn btn-outline",
      type: "button",
    }, ["Show as QR"]);
    const frames = el("div", { class: "qr-frames" });

    button.addEventListener("click", async () => {
      clear(frames);
      button.disabled = true;

      try {
        const res = await api("/shard-qr", {
          method: "POST",
          body: { path },
        });

        if (!Array.isArray(res.frames) || res.frames.length === 0) {
          throw new Error("No QR frames were returned for this file.");
        }

        res.frames.forEach((b64, index) => {
          const cell = el("div", { class: "qr-frame" });
          cell.appendChild(
            el("img", {
              src: "data:image/png;base64," + b64,
              alt: "QR frame " + (index + 1),
            })
          );
          if (res.frames.length > 1) {
            cell.appendChild(
              el("p", { class: "qr-frame-label" }, [
                "frame " + (index + 1) + "/" + res.frames.length,
              ])
            );
          }
          frames.appendChild(cell);
        });
      } catch (e) {
        clear(frames);
        frames.appendChild(banner("error", e.message));
      } finally {
        button.disabled = false;
      }
    });

    wrap.appendChild(button);
    wrap.appendChild(frames);
    return wrap;
  }

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).split(",").pop());
      reader.onerror = () => reject(reader.error || new Error("failed to read file"));
      reader.readAsDataURL(file);
    });
  }

  function wireQrImport(form, textareaName, inputId, buttonId, refresh) {
    const input = form.querySelector("#" + inputId);
    const button = form.querySelector("#" + buttonId);
    const textarea = form.querySelector('[name="' + textareaName + '"]');

    if (!input || !button || !textarea) return;

    button.addEventListener("click", async () => {
      const files = Array.from(input.files || []);
      if (!files.length) return;

      button.disabled = true;

      try {
        for (const file of files) {
          const png_base64 = await fileToBase64(file);
          const res = await api("/shard-qr-import", {
            method: "POST",
            body: { png_base64 },
          });
          const separator = textarea.value && !textarea.value.endsWith("\n") ? "\n" : "";
          textarea.value += separator + res.path;
        }

        input.value = "";
        if (refresh) refresh();
      } catch (e) {
        alert("QR import failed: " + e.message);
      } finally {
        button.disabled = false;
      }
    });
  }

  // ============================================================
  // MODE A SPLIT
  // ============================================================

  const initForm = document.getElementById("initForm");

  initForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();

    const result = document.getElementById("initResult");
    const data = formData(initForm);

    setBusy(initForm, true);
    clear(result);

    try {
      const shares = Number(data.shares);
      const selection = getSplitSelection(initPasswordFields, shares);

      const res = await api("/init", {
        method: "POST",
        body: {
          threshold: Number(data.threshold),
          shares,
          key_hex: data.key_hex || null,
          generate: !!data.generate,
          out_dir: data.out_dir,
          passwords: selection.passwords,
          devices: selection.devices,
        },
      });

      clear(result);

      if (res.generated_key_hex) {
        const b = banner(
          "warn",
          "Generated test key (shown once — never use for real funds):"
        );

        b.appendChild(
          el("div", { style: "margin-top:8px" }, [
            copyable("0x" + res.generated_key_hex),
          ])
        );

        result.appendChild(b);
      }

      result.appendChild(
        banner("ok", "Wrote " + res.paths.length + " shard(s) to " + res.out_dir)
      );

      result.appendChild(
        el(
          "ul",
          { class: "file-list" },
          res.paths.map((p) => el("li", {}, [p, qrShowButton(p)]))
        )
      );
    } catch (e) {
      clear(result);
      result.appendChild(banner("error", e.message));
    } finally {
      clearPasswordValues(initPasswordFields);
      setBusy(initForm, false);
    }
  });

  // ============================================================
  // MODE A SIGN
  // ============================================================

  const signForm = document.getElementById("signForm");
  wireQrImport(
    signForm,
    "shards",
    "qrImportInputSign",
    "qrImportBtnSign",
    refreshSignPasswordFields
  );

  signForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();

    const result = document.getElementById("signResult");
    const data = formData(signForm);

    setBusy(signForm, true);
    clear(result);

    try {
      const paths = lines(data.shards);
      const inputs = passwordInputs(signPasswordFields);

      if (inputs.length !== paths.length) {
        throw new Error(
          "The password fields are not ready for the selected files. Wait for threshold detection or re-enter the file paths."
        );
      }

      const requiredInputs = inputs.filter((input) => input.required);
      const threshold = requiredInputs.length;

      if (!threshold) {
        throw new Error(
          "The threshold has not been detected. Check the selected shard files."
        );
      }

      const selection = getSigningSelection(
        signPasswordFields,
        paths.length,
        threshold
      );

      const res = await api("/sign", {
        method: "POST",
        body: {
          shards: selection.paths,
          passwords: selection.passwords,
          to: data.to,
          lamports: Number(data.lamports),
          blockhash: data.blockhash || null,
          broadcast: !!data.broadcast,
          rpc_url: data.rpc_url || null,
          force: !!data.force,
        },
      });

      clear(result);

      if (res.warnings && res.warnings.length) {
        result.appendChild(
          banner("warn", "Audit warnings:", res.warnings)
        );
      }

      result.appendChild(
        kvTable([
          ["From", res.from],
          ["Signature", res.signature],
          ["Raw (base58)", res.raw_base58],
          ["Mined", res.mined_signature],
          ["Broadcast error", res.broadcast_error],
        ])
      );

      result.insertBefore(banner("ok", "Signed."), result.firstChild);
    } catch (e) {
      await handleBlocked(e, signForm, result);
    } finally {
      clearPasswordValues(signPasswordFields);
      setBusy(signForm, false);
    }
  });

  // ============================================================
  // MODE A RECONSTRUCT (standalone)
  // ============================================================

  const reconstructForm = document.getElementById("reconstructForm");

  wireQrImport(
    reconstructForm,
    "shards",
    "qrImportInputReconstruct",
    "qrImportBtnReconstruct",
    refreshReconstructPasswordFields
  );

  reconstructForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();

    const result = document.getElementById("reconstructResult");
    const data = formData(reconstructForm);

    setBusy(reconstructForm, true);
    clear(result);

    try {
      const paths = lines(data.shards);
      const inputs = passwordInputs(reconstructPasswordFields);

      if (inputs.length !== paths.length) {
        throw new Error(
          "The password fields are not ready for the selected files. Wait for threshold detection or re-enter the file paths."
        );
      }

      const threshold = inputs.filter((input) => input.required).length;

      if (!threshold) {
        throw new Error(
          "The threshold has not been detected. Check the selected shard files."
        );
      }

      const selection = getSigningSelection(
        reconstructPasswordFields,
        paths.length,
        threshold
      );

      const res = await api("/reconstruct", {
        method: "POST",
        body: {
          shards: selection.paths,
          passwords: selection.passwords,
          force: !!data.force,
        },
      });

      clear(result);

      result.appendChild(
        banner(
          "warn",
          "Reconstructed private key — handle with extreme care and do not copy it to an untrusted machine."
        )
      );

      if (res.warnings && res.warnings.length) {
        result.appendChild(banner("warn", "Audit warnings:", res.warnings));
      }

      result.appendChild(
        kvTable([
          ["Address", res.address],
          ["Private key (hex)", copyable(res.key_hex)],
        ])
      );
    } catch (e) {
      await handleBlocked(e, reconstructForm, result);
    } finally {
      clearPasswordValues(reconstructPasswordFields);
      setBusy(reconstructForm, false);
    }
  });

  // ============================================================
  // MODE B TABS
  // ============================================================

  const mpcTabs = document.querySelectorAll("[data-mpc-tab].tab");
  const mpcForms = document.querySelectorAll(".mpc-tab[data-mpc-tab]");

  mpcTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      mpcTabs.forEach((t) => t.classList.remove("is-active"));
      tab.classList.add("is-active");

      const which = tab.dataset.mpcTab;

      mpcForms.forEach((f) => {
        f.hidden = f.dataset.mpcTab !== which;
      });

      clear(document.getElementById("mpcResult"));
    });
  });
  // ============================================================
  // MODE B SPLIT
  // ============================================================

  document
    .getElementById("mpcSplitForm")
    .addEventListener("submit", async (ev) => {
      ev.preventDefault();

      const form = ev.target;
      const result = document.getElementById("mpcResult");
      const data = formData(form);

      setBusy(form, true);
      clear(result);

      try {
        const shares = Number(data.shares);
        const selection = getSplitSelection(mpcSplitPasswordFields, shares);

        const res = await api("/mpc-split", {
          method: "POST",
          body: {
            threshold: Number(data.threshold),
            shares,
            key_hex: data.key_hex || null,
            generate: !!data.generate,
            out_dir: data.out_dir,
            passwords: selection.passwords,
            devices: selection.devices,
          },
        });

        clear(result);

        if (res.generated_key_hex) {
          const b = banner(
            "warn",
            "Generated test key (shown once — never use for real funds):"
          );

          b.appendChild(
            el("div", { style: "margin-top:8px" }, [
              copyable("0x" + res.generated_key_hex),
            ])
          );

          result.appendChild(b);
        }

        result.appendChild(
          banner(
            "ok",
            "Wrote " + res.paths.length +
            " key share(s). Group package: " + res.group_path
          )
        );

        result.appendChild(
          el(
            "ul",
            { class: "file-list" },
            res.paths.map((p) => el("li", {}, [p, qrShowButton(p)]))
          )
        );
      } catch (e) {
        clear(result);
        result.appendChild(banner("error", e.message));
      } finally {
        clearPasswordValues(mpcSplitPasswordFields);
        setBusy(form, false);
      }
    });

  // ============================================================
  // MODE B SIGN
  // ============================================================

  const mpcSignForm = document.getElementById("mpcSignForm");
  wireQrImport(
    mpcSignForm,
    "shares",
    "qrImportInputMpcSign",
    "qrImportBtnMpcSign",
    refreshMpcSignPasswordFields
  );

  mpcSignForm.addEventListener("submit", async (ev) => {
      ev.preventDefault();

      const form = ev.target;
      const result = document.getElementById("mpcResult");
      const data = formData(form);

      setBusy(form, true);
      clear(result);

      try {
        const paths = lines(data.shares);
        const inputs = passwordInputs(mpcSignPasswordFields);

        if (inputs.length !== paths.length) {
          throw new Error(
            "The password fields are not ready for the selected files. Wait for threshold detection or re-enter the file paths."
          );
        }

        const requiredInputs = inputs.filter((input) => input.required);
        const threshold = requiredInputs.length;

        if (!threshold) {
          throw new Error(
            "The threshold has not been detected. Check the selected share files."
          );
        }

        const selection = getSigningSelection(
          mpcSignPasswordFields,
          paths.length,
          threshold
        );

        const res = await api("/mpc-sign", {
          method: "POST",
          body: {
            shares: selection.paths,
            group_dir: data.group_dir,
            passwords: selection.passwords,
            to: data.to,
            lamports: Number(data.lamports),
            blockhash: data.blockhash || null,
            broadcast: !!data.broadcast,
            rpc_url: data.rpc_url || null,
            force: !!data.force,
          },
        });

        clear(result);

        if (res.warnings && res.warnings.length) {
          result.appendChild(
            banner("warn", "Audit warnings:", res.warnings)
          );
        }

        result.appendChild(
          kvTable([
            ["From", res.from],
            ["Signature", res.signature],
            ["Raw (base58)", res.raw_base58],
            ["Mined", res.mined_signature],
            ["Broadcast error", res.broadcast_error],
          ])
        );

        result.insertBefore(
          banner("ok", "Signed with FROST."),
          result.firstChild
        );
      } catch (e) {
        await handleBlocked(e, form, result);
      } finally {
        clearPasswordValues(mpcSignPasswordFields);
        setBusy(form, false);
      }
    });

  // ============================================================
  // MODE B AIR-GAPPED QR SIGNING
  // ============================================================

  function dataUri(artifact) {
    return (
      "data:" + (artifact.mime || "application/octet-stream") +
      ";base64," + artifact.data_base64
    );
  }

  function renderArtifacts(container, artifacts) {
    if (!Array.isArray(artifacts) || artifacts.length === 0) return;

    const grid = el("div", { class: "qr-artifacts" });

    artifacts.forEach((artifact, index) => {
      const card = el("div", { class: "qr-artifact" });
      const uri = dataUri(artifact);

      if (artifact.mime === "image/png") {
        card.appendChild(
          el("img", {
            src: uri,
            alt: artifact.filename || "QR frame " + (index + 1),
          })
        );
      } else {
        card.appendChild(
          el("div", { class: "qr-file-icon" }, ["HX3"])
        );
      }

      card.appendChild(
        el("a", {
          class: "qr-download",
          href: uri,
          download: artifact.filename || "artifact",
        }, ["download " + (artifact.filename || "artifact")])
      );

      if (artifact.path) {
        card.appendChild(el("p", { class: "qr-artifact-path" }, [artifact.path]));
      }

      grid.appendChild(card);
    });

    container.appendChild(grid);
  }

  function renderQrResult(result, data, successTitle) {
    if (data.warnings && data.warnings.length) {
      result.appendChild(banner("warn", "Audit warnings:", data.warnings));
    }

    result.appendChild(banner("ok", successTitle));

    result.appendChild(
      kvTable([
        ["From", data.from],
        ["To", data.to],
        ["Lamports", data.lamports],
        ["Session", data.session],
        ["Directory", data.dir],
        ["Participant", data.participant_id],
        ["Participants", Array.isArray(data.ids) ? data.ids.join(", ") : undefined],
        ["Nonce file (local)", data.nonce_path],
        ["Signature", data.signature],
        ["Raw (base58)", data.raw_base58],
        ["Mined", data.mined_signature],
        ["Broadcast error", data.broadcast_error],
      ])
    );

    if (data.artifacts) {
      result.appendChild(el("h3", {}, ["Air-gap artifacts"]));
      renderArtifacts(result, data.artifacts);
    }
  }

  async function qrSubmit(ev, endpoint, resultId, successTitle, buildBody) {
    ev.preventDefault();

    const form = ev.target;
    const result = document.getElementById(resultId);
    const data = formData(form);

    setBusy(form, true);
    clear(result);

    try {
      const body = buildBody(data);
      const res = await api(endpoint, { method: "POST", body });

      clear(result);
      renderQrResult(result, res, successTitle);
    } catch (e) {
      clear(result);

      if (e.status === 409 && e.data && e.data.reasons) {
        result.appendChild(
          banner("error", "Audit blocked this attempt:", e.data.reasons)
        );

        const forceField = form.querySelector(".force-field");

        if (forceField) {
          forceField.hidden = false;
          forceField.querySelector("input").checked = true;
        }

        result.appendChild(
          el("p", {}, [
            "Review the audit warning. If you retry, enter the password again.",
          ])
        );
      } else {
        result.appendChild(banner("error", e.message));
      }
    } finally {
      form
        .querySelectorAll('input[type="password"]')
        .forEach((input) => (input.value = ""));
      setBusy(form, false);
    }
  }

  document
    .getElementById("qrRequestForm")
    .addEventListener("submit", (ev) =>
      qrSubmit(
        ev,
        "/qr-request",
        "qrRequestResult",
        "Signing request written to the air-gap directory.",
        (d) => ({
          group_dir: d.group_dir,
          to: d.to,
          lamports: Number(d.lamports),
          blockhash: d.blockhash,
          dir: d.dir,
          format: d.format,
        })
      )
    );

  document
    .getElementById("qrCommitForm")
    .addEventListener("submit", (ev) =>
      qrSubmit(
        ev,
        "/qr-commit",
        "qrCommitResult",
        "Commitment written to the air-gap directory.",
        (d) => ({
          share: d.share,
          password: d.password,
          dir: d.dir,
          nonce_file: d.nonce_file || null,
          format: d.format,
          force: !!d.force,
        })
      )
    );

  document
    .getElementById("qrPackageForm")
    .addEventListener("submit", (ev) =>
      qrSubmit(
        ev,
        "/qr-package",
        "qrPackageResult",
        "Signing package written to the air-gap directory.",
        (d) => ({
          dir: d.dir,
          format: d.format,
        })
      )
    );

  document
    .getElementById("qrShareForm")
    .addEventListener("submit", (ev) =>
      qrSubmit(
        ev,
        "/qr-share",
        "qrShareResult",
        "Signature share written to the air-gap directory.",
        (d) => ({
          share: d.share,
          password: d.password,
          dir: d.dir,
          nonce_file: d.nonce_file || null,
          format: d.format,
          force: !!d.force,
        })
      )
    );

  document
    .getElementById("qrFinalizeForm")
    .addEventListener("submit", (ev) =>
      qrSubmit(
        ev,
        "/qr-finalize",
        "qrFinalizeResult",
        "Signature aggregated and verified.",
        (d) => ({
          dir: d.dir,
          rpc_url: d.rpc_url || null,
          broadcast: !!d.broadcast,
        })
      )
    );

  const qrImportForm = document.getElementById("qrImportForm");

  qrImportForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();

    const result = document.getElementById("qrImportResult");
    const data = formData(qrImportForm);
    const input = document.getElementById("qrImportFiles");
    const files = Array.from(input.files || []);

    clear(result);

    if (!files.length) {
      result.appendChild(banner("error", "choose at least one PNG or .hx3 file"));
      return;
    }

    setBusy(qrImportForm, true);

    try {
      const payload = [];

      for (const file of files) {
        payload.push({
          filename: file.name,
          data_base64: await fileToBase64(file),
        });
      }

      const res = await api("/qr-import", {
        method: "POST",
        body: { dir: data.dir, files: payload },
      });

      clear(result);
      result.appendChild(
        banner("ok", "Imported " + res.messages.length + " message(s) into " + res.dir)
      );

      res.messages.forEach((message) => {
        const block = el("div", { class: "qr-imported" });

        block.appendChild(
          el("h3", {}, [
            message.label +
            (message.participant_id != null
              ? " · participant " + message.participant_id
              : ""),
          ])
        );

        block.appendChild(
          kvTable([
            ["Type", message.message_type],
            ["Session", message.session],
          ])
        );

        if (message.artifacts) {
          renderArtifacts(block, message.artifacts);
        }

        result.appendChild(block);
      });

      input.value = "";
    } catch (e) {
      clear(result);
      result.appendChild(banner("error", "Import failed: " + e.message));
    } finally {
      setBusy(qrImportForm, false);
    }
  });

  // ============================================================
  // AI SECURITY CHECK
  // ============================================================

  const aiCheckButton = document.getElementById("aiCheckButton");
  const aiCheckResult = document.getElementById("aiCheckResult");

  aiCheckButton.addEventListener("click", async () => {
    aiCheckButton.disabled = true;
    aiCheckButton.textContent = "Checking...";

    clear(aiCheckResult);

    aiCheckResult.appendChild(
      el("p", {}, ["Analysing the latest access-log entries..."])
    );

    try {
      const res = await api("/ai-check");

      clear(aiCheckResult);

      aiCheckResult.appendChild(
        banner(
          res.anomaly ? "warn" : "ok",
          res.anomaly
            ? "Possible anomaly flagged by AI."
            : "No unusual activity flagged by AI."
        )
      );

      aiCheckResult.appendChild(
        kvTable([
          ["Model", res.model],
          ["Entries analysed", res.entries_analyzed],
          ["AI explanation", res.summary],
        ])
      );
    } catch (e) {
      clear(aiCheckResult);
      aiCheckResult.appendChild(banner("error", e.message));
    } finally {
      aiCheckButton.disabled = false;
      aiCheckButton.textContent = "AI Log Analysis";
    }
  });
})();
