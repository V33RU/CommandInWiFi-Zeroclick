(function () {
    "use strict";

    // ====================================================================
    // Tab Navigation
    // ====================================================================
    var tabs = document.querySelectorAll(".tab");
    var panels = document.querySelectorAll(".panel");

    tabs.forEach(function (tab) {
        tab.addEventListener("click", function () {
            tabs.forEach(function (t) { t.classList.remove("active"); });
            panels.forEach(function (p) { p.classList.add("hidden"); });
            tab.classList.add("active");
            document.getElementById("panel-" + tab.dataset.panel).classList.remove("hidden");

            if (tab.dataset.panel === "payloads") loadPayloads();
            if (tab.dataset.panel === "results") loadMatrix();
            if (tab.dataset.panel === "serial") refreshPorts();
        });
    });

    // ====================================================================
    // Utilities
    // ====================================================================
    function escapeHtml(str) {
        var div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    function truncate(str, len) {
        return str.length > len ? str.slice(0, len) + "..." : str;
    }

    // Toast notification (replaces alert())
    var toastTimer = null;
    function showToast(message, type) {
        var existing = document.getElementById("toast");
        if (existing) existing.remove();

        var el = document.createElement("div");
        el.id = "toast";
        el.className = "toast " + (type || "error");
        el.textContent = message;
        document.body.appendChild(el);

        // Trigger animation
        requestAnimationFrame(function () {
            el.classList.add("show");
        });

        clearTimeout(toastTimer);
        toastTimer = setTimeout(function () {
            el.classList.remove("show");
            setTimeout(function () { el.remove(); }, 300);
        }, 4000);
    }

    // ====================================================================
    // Selection State
    // ====================================================================
    var selectedIds = new Set();

    function updateDeployButton() {
        var btn = document.getElementById("btn-deploy");
        var count = selectedIds.size;
        btn.textContent = "Deploy Selected (" + count + ")";
        btn.disabled = count === 0;
    }

    function updateSelectAllCheckbox() {
        var all = document.getElementById("select-all");
        var checkboxes = document.querySelectorAll(".payload-check");
        if (checkboxes.length === 0) {
            all.checked = false;
            all.indeterminate = false;
            return;
        }
        var checked = document.querySelectorAll(".payload-check:checked").length;
        all.checked = checked === checkboxes.length;
        all.indeterminate = checked > 0 && checked < checkboxes.length;
    }

    function updateRowHighlight(row, isSelected) {
        if (isSelected) {
            row.classList.add("selected");
        } else {
            row.classList.remove("selected");
        }
    }

    // Select All handler — only toggles visible (filtered) checkboxes
    document.getElementById("select-all").addEventListener("change", function () {
        var checked = this.checked;
        document.querySelectorAll(".payload-check").forEach(function (cb) {
            cb.checked = checked;
            var id = parseInt(cb.dataset.id);
            var row = cb.closest("tr");
            if (checked) {
                selectedIds.add(id);
            } else {
                selectedIds.delete(id);
            }
            updateRowHighlight(row, checked);
        });
        updateDeployButton();
    });

    // ====================================================================
    // Payload Manager
    // ====================================================================
    var categoryFilter = document.getElementById("category-filter");

    // Clear selections when switching category — avoids confusing counts
    categoryFilter.addEventListener("change", function () {
        selectedIds.clear();
        document.getElementById("select-all").checked = false;
        document.getElementById("select-all").indeterminate = false;
        updateDeployButton();
        loadPayloads();
    });

    document.getElementById("btn-add-payload").addEventListener("click", function () {
        document.getElementById("modal-title").textContent = "Add Payload";
        document.getElementById("modal-payload-id").value = "";
        document.getElementById("modal-text").value = "";
        document.getElementById("modal-category").value = "wifi_cmd";
        document.getElementById("modal-description").value = "";
        document.getElementById("payload-modal").classList.remove("hidden");
    });

    document.getElementById("modal-cancel").addEventListener("click", function () {
        document.getElementById("payload-modal").classList.add("hidden");
    });

    document.getElementById("modal-save").addEventListener("click", async function () {
        var id = document.getElementById("modal-payload-id").value;
        var body = {
            text: document.getElementById("modal-text").value,
            category: document.getElementById("modal-category").value,
            description: document.getElementById("modal-description").value,
        };
        if (!body.text) return;

        if (id) {
            await fetch("/api/payloads/" + id, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
        } else {
            await fetch("/api/payloads", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
        }
        document.getElementById("payload-modal").classList.add("hidden");
        loadPayloads();
    });

    async function loadPayloads() {
        var category = categoryFilter.value;
        var url = category ? "/api/payloads?category=" + category : "/api/payloads";
        var res = await fetch(url);
        var payloads = await res.json();
        renderPayloadsTable(payloads);
    }

    function renderPayloadsTable(payloads) {
        var tbody = document.getElementById("payloads-body");
        tbody.innerHTML = payloads
            .map(function (p) {
                var isSelected = selectedIds.has(p.id);
                var checked = isSelected ? " checked" : "";
                var rowClass = isSelected ? ' class="selected"' : "";
                return (
                    '<tr' + rowClass + ' data-row-id="' + p.id + '">' +
                    '<td class="td-check"><input type="checkbox" class="payload-check" data-id="' + p.id + '"' + checked + '></td>' +
                    '<td><code>' + escapeHtml(p.text) + '</code></td>' +
                    '<td><span class="badge cat-' + escapeHtml(p.category) + '">' + escapeHtml(p.category) + '</span></td>' +
                    '<td>' + escapeHtml(p.description) + '</td>' +
                    '<td class="actions-cell">' +
                    '<button class="btn-sm" data-edit="' + p.id + '">Edit</button> ' +
                    '<button class="btn-danger" data-del="' + p.id + '">Del</button>' +
                    '</td>' +
                    '</tr>'
                );
            })
            .join("");

        // Row click handler — toggle checkbox when clicking anywhere on the row
        tbody.querySelectorAll("tr").forEach(function (row) {
            row.addEventListener("click", function (e) {
                // Don't toggle if user clicked a button (Edit/Del)
                if (e.target.closest("button")) return;

                var cb = row.querySelector(".payload-check");
                if (!cb) return;

                // If user clicked the checkbox itself, don't double-toggle
                if (e.target === cb) return;

                cb.checked = !cb.checked;
                cb.dispatchEvent(new Event("change"));
            });
        });

        // Checkbox change handlers
        tbody.querySelectorAll(".payload-check").forEach(function (cb) {
            cb.addEventListener("change", function () {
                var id = parseInt(cb.dataset.id);
                var row = cb.closest("tr");
                if (cb.checked) {
                    selectedIds.add(id);
                    updateRowHighlight(row, true);
                } else {
                    selectedIds.delete(id);
                    updateRowHighlight(row, false);
                }
                updateDeployButton();
                updateSelectAllCheckbox();
            });
        });

        // Edit handlers
        tbody.querySelectorAll("[data-edit]").forEach(function (btn) {
            btn.addEventListener("click", function (e) {
                e.stopPropagation();
                var id = btn.dataset.edit;
                var p = payloads.find(function (x) { return x.id == id; });
                if (!p) return;
                document.getElementById("modal-title").textContent = "Edit Payload";
                document.getElementById("modal-payload-id").value = p.id;
                document.getElementById("modal-text").value = p.text;
                document.getElementById("modal-category").value = p.category;
                document.getElementById("modal-description").value = p.description;
                document.getElementById("payload-modal").classList.remove("hidden");
            });
        });

        // Delete handlers
        tbody.querySelectorAll("[data-del]").forEach(function (btn) {
            btn.addEventListener("click", async function (e) {
                e.stopPropagation();
                if (!confirm("Delete this payload?")) return;
                await fetch("/api/payloads/" + btn.dataset.del, { method: "DELETE" });
                selectedIds.delete(parseInt(btn.dataset.del));
                updateDeployButton();
                loadPayloads();
            });
        });

        updateSelectAllCheckbox();
        updateDeployButton();
    }

    // ====================================================================
    // Deploy to ESP
    // ====================================================================
    // Helper: switch to Serial Monitor tab
    function switchToSerialTab() {
        tabs.forEach(function (t) { t.classList.remove("active"); });
        panels.forEach(function (p) { p.classList.add("hidden"); });
        var serialTab = document.querySelector('[data-panel="serial"]');
        serialTab.classList.add("active");
        document.getElementById("panel-serial").classList.remove("hidden");
        refreshPorts();
    }

    document.getElementById("btn-deploy").addEventListener("click", async function () {
        var ids = Array.from(selectedIds);
        if (ids.length === 0) return;

        var btn = document.getElementById("btn-deploy");
        btn.disabled = true;
        btn.textContent = "Deploying " + ids.length + "...";
        updateESPBadge("deploying", ids.length);

        // Switch to Serial Monitor FIRST so user sees progress live
        switchToSerialTab();

        try {
            var res = await fetch("/api/deploy", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ payload_ids: ids }),
            });
            var data = await res.json();

            if (res.ok && data.ok) {
                updateESPBadge("broadcasting", data.count);
                showToast("ESP broadcasting " + data.count + " payloads", "success");
            } else {
                showToast("Deploy failed: " + (data.detail || data.error || "Unknown error"), "error");
                updateESPBadge("idle", 0);
            }
        } catch (e) {
            showToast("Deploy error: " + e.message, "error");
            updateESPBadge("idle", 0);
        }

        btn.textContent = "Deploy Selected (" + selectedIds.size + ")";
        btn.disabled = selectedIds.size === 0;
    });

    document.getElementById("btn-stop-esp").addEventListener("click", async function () {
        switchToSerialTab();
        await fetch("/api/deploy/stop", { method: "POST" });
        updateESPBadge("stopped", 0);
        showToast("ESP stopped", "success");
    });

    function updateESPBadge(status, count) {
        var badge = document.getElementById("esp-status");
        badge.className = "esp-badge " + status;
        if (status === "broadcasting" || status === "running") {
            badge.textContent = "ESP: Broadcasting " + count + " payloads";
        } else if (status === "deploying") {
            badge.textContent = "ESP: Deploying " + count + "...";
        } else if (status === "stopped") {
            badge.textContent = "ESP: Stopped";
        } else {
            badge.textContent = "ESP: Idle";
        }
    }

    // Poll ESP status every 5 seconds
    setInterval(async function () {
        try {
            var res = await fetch("/api/deploy/status");
            var data = await res.json();
            if (data.connected) {
                updateESPBadge(data.deploy_status, data.deploy_count);
            }
        } catch (e) { /* ignore */ }
    }, 5000);

    // ====================================================================
    // Results Matrix
    // ====================================================================
    document.getElementById("btn-refresh-matrix").addEventListener("click", loadMatrix);

    document.getElementById("btn-add-result").addEventListener("click", async function () {
        var res = await fetch("/api/payloads");
        var payloads = await res.json();
        var sel = document.getElementById("result-payload");
        sel.innerHTML = payloads
            .map(function (p) {
                return '<option value="' + p.id + '">' + escapeHtml(truncate(p.text, 30)) + ' (' + p.category + ')</option>';
            })
            .join("");
        document.getElementById("result-device-name").value = "";
        document.getElementById("result-device-mac").value = "";
        document.getElementById("result-status").value = "crashed";
        document.getElementById("result-notes").value = "";
        document.getElementById("result-modal").classList.remove("hidden");
    });

    document.getElementById("result-cancel").addEventListener("click", function () {
        document.getElementById("result-modal").classList.add("hidden");
    });

    document.getElementById("result-save").addEventListener("click", async function () {
        var body = {
            payload_id: parseInt(document.getElementById("result-payload").value),
            device_name: document.getElementById("result-device-name").value,
            device_mac: document.getElementById("result-device-mac").value,
            status: document.getElementById("result-status").value,
            notes: document.getElementById("result-notes").value,
        };
        if (!body.device_name) return;
        await fetch("/api/results", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        document.getElementById("result-modal").classList.add("hidden");
        loadMatrix();
    });

    async function loadMatrix() {
        var res = await fetch("/api/results/matrix");
        var data = await res.json();
        renderMatrix(data);
    }

    function renderMatrix(data) {
        var container = document.getElementById("matrix-container");
        if (data.devices.length === 0) {
            container.innerHTML = '<p class="muted">No test results yet. Record your first result.</p>';
            return;
        }
        var html = '<table class="matrix-table"><thead><tr><th>Device</th>';
        data.payloads.forEach(function (p) {
            html += '<th title="' + escapeHtml(p.text) + '"><code>' + escapeHtml(truncate(p.text, 12)) + '</code></th>';
        });
        html += "</tr></thead><tbody>";
        data.devices.forEach(function (device) {
            html += '<tr><td class="device-name">' + escapeHtml(device) + "</td>";
            data.payloads.forEach(function (p) {
                var cell = data.matrix[device] && data.matrix[device][p.id];
                if (cell) {
                    html += '<td class="cell-' + cell.status + '" title="' + escapeHtml(cell.tested_at) + '">' +
                        '<span class="cell-text">' + cell.status + '</span>' +
                        '<button class="cell-del" data-result-id="' + cell.id + '" title="Delete result">x</button>' +
                        "</td>";
                } else {
                    html += '<td class="cell-untested">-</td>';
                }
            });
            html += "</tr>";
        });
        html += "</tbody></table>";
        container.innerHTML = html;

        // Delete result handlers
        container.querySelectorAll(".cell-del").forEach(function (btn) {
            btn.addEventListener("click", async function (e) {
                e.stopPropagation();
                if (!confirm("Delete this result?")) return;
                btn.disabled = true;
                try {
                    var res = await fetch("/api/results/" + btn.dataset.resultId, { method: "DELETE" });
                    if (res.ok) {
                        showToast("Result deleted", "success");
                        loadMatrix();
                    } else {
                        showToast("Delete failed", "error");
                    }
                } catch (err) {
                    showToast("Delete error: " + err.message, "error");
                }
            });
        });
    }

    // ====================================================================
    // Serial Monitor
    // ====================================================================
    var ws = null;

    async function refreshPorts() {
        var res = await fetch("/api/serial/ports");
        var ports = await res.json();
        var sel = document.getElementById("serial-port");
        if (ports.length > 0) {
            sel.innerHTML = ports
                .map(function (p) {
                    return '<option value="' + escapeHtml(p.device) + '">' + escapeHtml(p.device) + " - " + escapeHtml(p.description) + "</option>";
                })
                .join("");
        } else {
            sel.innerHTML = '<option value="">No ports found</option>';
        }

        // Check current status
        var statusRes = await fetch("/api/serial/status");
        var status = await statusRes.json();
        updateSerialUI(status.connected);
    }

    document.getElementById("btn-serial-connect").addEventListener("click", async function () {
        var port = document.getElementById("serial-port").value;
        if (!port) return;
        var baud = parseInt(document.getElementById("serial-baud").value);
        await fetch("/api/serial/connect", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ port: port, baud: baud }),
        });
        connectWebSocket();
        updateSerialUI(true);
    });

    document.getElementById("btn-serial-disconnect").addEventListener("click", async function () {
        await fetch("/api/serial/disconnect", { method: "POST" });
        if (ws) ws.close();
        updateSerialUI(false);
    });

    document.getElementById("btn-serial-clear").addEventListener("click", function () {
        document.getElementById("serial-output").textContent = "";
    });

    // Flash Firmware button
    document.getElementById("btn-flash-firmware").addEventListener("click", async function () {
        var port = document.getElementById("serial-port").value;
        var board = document.getElementById("board-select").value;
        if (!port) {
            showToast("Select a serial port first", "error");
            return;
        }
        var boardLabel = board === "esp32" ? "ESP32" : "ESP8266";
        if (!confirm("Flash CommandInWiFi firmware to " + boardLabel + " on " + port + "?\n\nThis will compile and upload the firmware. The ESP will reboot after flashing.")) {
            return;
        }

        var btn = document.getElementById("btn-flash-firmware");
        btn.disabled = true;
        btn.textContent = "Flashing " + boardLabel + "...";

        // Ensure WebSocket is open to see progress
        connectWebSocket();

        try {
            var res = await fetch("/api/firmware/flash", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ port: port, board: board }),
            });
            var data = await res.json();

            if (res.ok && data.ok) {
                showToast("Firmware flashed successfully!", "success");
                updateSerialUI(true);
            } else {
                showToast("Flash failed: " + (data.detail || data.error || "Unknown error"), "error");
            }
        } catch (e) {
            showToast("Flash error: " + e.message, "error");
        }

        btn.disabled = false;
        btn.textContent = "Flash Firmware";
    });

    document.getElementById("btn-serial-send").addEventListener("click", function () {
        var input = document.getElementById("serial-input");
        if (ws && ws.readyState === WebSocket.OPEN && input.value) {
            ws.send(input.value);
            input.value = "";
        }
    });

    document.getElementById("serial-input").addEventListener("keydown", function (e) {
        if (e.key === "Enter") document.getElementById("btn-serial-send").click();
    });

    function connectWebSocket() {
        var protocol = location.protocol === "https:" ? "wss:" : "ws:";
        ws = new WebSocket(protocol + "//" + location.host + "/ws/serial");
        ws.onmessage = function (event) {
            var msg = event.data;
            var output = document.getElementById("serial-output");

            // Color-code special messages in terminal
            if (msg.startsWith("[DEPLOY]") || msg.startsWith("[FLASH]")) {
                output.innerHTML += '<span class="term-device">' + escapeHtml(msg) + '</span>\n';
            } else {
                output.textContent += msg + "\n";
            }

            // Auto-scroll and limit buffer to prevent memory issues
            if (output.childNodes.length > 2000) {
                while (output.childNodes.length > 1500) {
                    output.removeChild(output.firstChild);
                }
            }
            output.scrollTop = output.scrollHeight;
        };
        ws.onclose = function () {
            updateSerialUI(false);
        };
    }

    function updateSerialUI(connected) {
        var badge = document.getElementById("serial-status");
        badge.textContent = connected ? "Connected" : "Disconnected";
        badge.className = "status-badge " + (connected ? "connected" : "disconnected");
        document.getElementById("btn-serial-connect").disabled = connected;
        document.getElementById("btn-serial-disconnect").disabled = !connected;
        document.getElementById("serial-input").disabled = !connected;
        document.getElementById("btn-serial-send").disabled = !connected;
    }

    // ====================================================================
    // Device Tracker
    // ====================================================================
    function renderDeviceList(devices) {
        var container = document.getElementById("device-list");
        var countEl = document.getElementById("device-count");
        countEl.textContent = devices.length;

        if (devices.length === 0) {
            container.innerHTML = '<p class="muted">No devices connected</p>';
            return;
        }

        container.innerHTML = devices.map(function (d) {
            var ago = Math.round((Date.now() / 1000) - d.connected_at);
            var timeStr = ago < 60 ? ago + "s ago" : Math.round(ago / 60) + "m ago";
            return (
                '<div class="device-card">' +
                '<div class="device-mac">' + escapeHtml(d.mac) + '</div>' +
                '<div class="device-info">' +
                '<span class="device-ssid" title="' + escapeHtml(d.ssid) + '">SSID: ' + escapeHtml(truncate(d.ssid, 16)) + '</span>' +
                '<span class="device-time">' + timeStr + '</span>' +
                '</div></div>'
            );
        }).join("");
    }

    function renderVulnLog(vulns) {
        var container = document.getElementById("vuln-log");
        var countEl = document.getElementById("vuln-count");
        countEl.textContent = vulns.length;

        if (vulns.length === 0) {
            container.innerHTML = '<p class="muted">No vulnerabilities detected yet</p>';
            return;
        }

        container.innerHTML = vulns.slice().reverse().map(function (v) {
            var vuln = v.vuln || "crash";
            var dur = v.duration ? v.duration.toFixed(1) + "s" : "?";

            return (
                '<div class="vuln-entry vuln-crash">' +
                '<div class="vuln-row-top">' +
                '<span class="vuln-badge">CRASH</span>' +
                '</div>' +
                '<div class="vuln-row-bottom">' +
                '<span class="vuln-mac">' + escapeHtml(v.mac) + '</span> ' +
                '<span class="vuln-detail">disconnected after ' + dur +
                ' on <code>' + escapeHtml(truncate(v.ssid || "", 18)) + '</code></span>' +
                '</div>' +
                '<button class="vuln-save-btn" data-mac="' + escapeHtml(v.mac) + '" ' +
                'data-ssid="' + escapeHtml(v.ssid || "") + '" ' +
                'data-vuln="' + escapeHtml(vuln) + '">Save to Results</button>' +
                '</div>'
            );
        }).join("");

        // Attach save handlers
        container.querySelectorAll(".vuln-save-btn").forEach(function (btn) {
            btn.addEventListener("click", async function () {
                btn.disabled = true;
                btn.textContent = "Saving...";
                try {
                    var res = await fetch("/api/devices/save-result", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            mac: btn.dataset.mac,
                            ssid: btn.dataset.ssid,
                            vuln_type: btn.dataset.vuln,
                        }),
                    });
                    if (res.ok) {
                        btn.textContent = "Saved";
                        btn.className = "vuln-save-btn saved";
                        showToast("Result saved to matrix", "success");
                    } else {
                        var err = await res.json();
                        btn.textContent = "Failed";
                        showToast("Save failed: " + (err.detail || "Unknown"), "error");
                    }
                } catch (e) {
                    btn.textContent = "Error";
                    showToast("Save error: " + e.message, "error");
                }
            });
        });
    }

    // Poll device state every 5 seconds
    setInterval(async function () {
        try {
            var res = await fetch("/api/devices");
            var data = await res.json();
            renderDeviceList(data.connected);
            renderVulnLog(data.vulns);
        } catch (e) { /* ignore */ }
    }, 5000);

    // ====================================================================
    // Init
    // ====================================================================
    loadPayloads();
})();
