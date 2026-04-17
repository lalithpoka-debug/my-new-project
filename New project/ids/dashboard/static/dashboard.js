async function fetchStatus() {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) {
        throw new Error(`Dashboard API returned ${response.status}`);
    }
    return response.json();
}

const metricPalettes = {
    "protocol-list": [
        ["#56d6c2", "#7fc9ff"],
        ["#7fc9ff", "#a98cff"],
        ["#a8f08c", "#56d6c2"],
        ["#ffcf70", "#ff9d63"],
        ["#ff8fb1", "#a98cff"]
    ],
    "severity-list": [
        ["#56d6c2", "#a8f08c"],
        ["#ffcf70", "#ff9d63"],
        ["#ff8fb1", "#ff7f7f"],
        ["#ff7f7f", "#ff9d63"]
    ]
};

function renderMetricList(containerId, metrics) {
    const container = document.getElementById(containerId);
    const entries = Object.entries(metrics || {});
    if (!entries.length) {
        container.innerHTML = '<div class="empty-state">No data available yet.</div>';
        return;
    }

    const maxValue = Math.max(...entries.map(([, value]) => Number(value)));
    const palette = metricPalettes[containerId] || metricPalettes["protocol-list"];
    container.innerHTML = entries
        .sort((a, b) => Number(b[1]) - Number(a[1]))
        .map(([label, value], index) => {
            const width = maxValue ? (Number(value) / maxValue) * 100 : 0;
            const [startColor, endColor] = palette[index % palette.length];
            return `
                <div class="metric-item" style="--metric-start: ${startColor}; --metric-end: ${endColor};">
                    <div>
                        <span>${label}</span>
                        <div class="metric-track">
                            <div class="metric-fill" style="width: ${width}%"></div>
                        </div>
                    </div>
                    <strong>${value}</strong>
                </div>
            `;
        })
        .join("");
}

function renderTableRows(containerId, rows, rowBuilder, emptyMessage, colSpan = 6) {
    const container = document.getElementById(containerId);
    if (!rows || !rows.length) {
        container.innerHTML = `<tr><td colspan="${colSpan}" class="empty-state">${emptyMessage}</td></tr>`;
        return;
    }
    container.innerHTML = rows.map(rowBuilder).join("");
}

function severityPill(severity) {
    const normalized = (severity || "LOW").toLowerCase();
    return `<span class="severity-pill ${normalized}">${severity}</span>`;
}

function protocolPill(protocol) {
    const normalized = (protocol || "OTHER").toLowerCase();
    return `<span class="protocol-pill ${normalized}">${protocol}</span>`;
}

function rowTintClass(severity) {
    const normalized = (severity || "").toLowerCase();
    if (!normalized) {
        return "";
    }
    return `row-tint-${normalized}`;
}

function countBadge(value) {
    return `<span class="count-badge">${value}</span>`;
}

function ipChip(ip, startColor, endColor) {
    return `
        <span class="ip-chip" style="--metric-start: ${startColor}; --metric-end: ${endColor};">
            ${ip}
        </span>
    `;
}

function renderDashboard(data) {
    document.getElementById("total-packets").textContent = data.total_packets ?? 0;
    document.getElementById("packets-last-10s").textContent = data.packets_last_10s ?? 0;
    document.getElementById("total-alerts").textContent = data.total_alerts ?? 0;
    document.getElementById("last-packet-time").textContent =
        data.last_packet_time ?? "No traffic yet";

    renderMetricList("protocol-list", data.protocols);
    renderMetricList("severity-list", data.severities);

    renderTableRows(
        "top-sources",
        data.top_sources,
        (item, index) => {
            const palette = [
                ["#a98cff", "#ff8fb1"],
                ["#7fc9ff", "#56d6c2"],
                ["#ffcf70", "#ff9d63"]
            ][index % 3];
            return `<tr><td>${ipChip(item.ip, palette[0], palette[1])}</td><td>${countBadge(item.count)}</td></tr>`;
        },
        "No source IP statistics yet.",
        2
    );

    renderTableRows(
        "top-destinations",
        data.top_destinations,
        (item, index) => {
            const palette = [
                ["#a8f08c", "#56d6c2"],
                ["#7fc9ff", "#a98cff"],
                ["#ffcf70", "#ff9d63"]
            ][index % 3];
            return `<tr><td>${ipChip(item.ip, palette[0], palette[1])}</td><td>${countBadge(item.count)}</td></tr>`;
        },
        "No destination IP statistics yet.",
        2
    );

    renderTableRows(
        "recent-alerts",
        data.recent_alerts,
        item => `
            <tr class="${rowTintClass(item.severity)}">
                <td>${item.timestamp}</td>
                <td>${severityPill(item.severity)}</td>
                <td>${item.rule_id}</td>
                <td>${item.source}</td>
                <td>${item.destination}</td>
                <td>${item.message}</td>
            </tr>
        `,
        "No alerts generated yet."
    );

    renderTableRows(
        "recent-packets",
        data.recent_packets,
        item => `
            <tr>
                <td>${item.timestamp}</td>
                <td>${protocolPill(item.protocol)}</td>
                <td>${item.src_ip}${item.src_port ? `:${item.src_port}` : ""}</td>
                <td>${item.dst_ip}${item.dst_port ? `:${item.dst_port}` : ""}</td>
                <td>${countBadge(item.length)}</td>
                <td>${item.tcp_flags || "-"}</td>
            </tr>
        `,
        "No packets captured yet."
    );
}

async function refreshDashboard() {
    try {
        const data = await fetchStatus();
        renderDashboard(data);
    } catch (error) {
        console.error(error);
    }
}

refreshDashboard();
setInterval(refreshDashboard, window.REFRESH_INTERVAL_MS || 2000);
