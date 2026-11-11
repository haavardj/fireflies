// Draws the /graphs page from /api/history with Chart.js.
(function () {
  "use strict";

  const root = document.querySelector(".charts");
  const interval = Number(root.dataset.interval) || 10;
  const charts = {};

  // Colours come from CSS custom properties, so light and dark mode each
  // use their own validated steps.
  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function colours(chartName, labels) {
    if (chartName === "members") {
      const status = { live: "--live", accused: "--accused", failed: "--failed" };
      return labels.map((l) => css(status[l]));
    }
    return labels.map((_, i) => css("--series-" + (i + 1)));
  }

  function clock(ms, seconds) {
    const opts = { hour: "2-digit", minute: "2-digit" };
    if (seconds) opts.second = "2-digit";
    return new Date(ms).toLocaleTimeString([], opts);
  }

  function number(v) {
    return v.toLocaleString(undefined, { maximumFractionDigits: v < 10 ? 2 : 0 });
  }

  // Draws each series' name at the right end of its line. Labels that
  // would overlap are pushed apart vertically.
  const endLabels = {
    id: "endLabels",
    afterDatasetsDraw(chart) {
      const { ctx, chartArea } = chart;
      const items = [];
      chart.data.datasets.forEach((ds, i) => {
        const meta = chart.getDatasetMeta(i);
        if (meta.hidden || !meta.data.length) return;
        const p = meta.data[meta.data.length - 1];
        items.push({ y: p.y, text: ds.label, colour: ds.borderColor });
      });
      // Keep labels inside the plot, 14px apart: push down, then shift
      // the whole stack up if it runs past the bottom.
      const gap = 14, top = chartArea.top + 6, bottom = chartArea.bottom - 6;
      items.forEach((it) => { it.y = Math.min(Math.max(it.y, top), bottom); });
      items.sort((a, b) => a.y - b.y);
      for (let i = 1; i < items.length; i++) {
        items[i].y = Math.max(items[i].y, items[i - 1].y + gap);
      }
      const over = items.length ? items[items.length - 1].y - bottom : 0;
      if (over > 0) items.forEach((it) => { it.y -= over; });
      ctx.save();
      ctx.font = "12px system-ui, -apple-system, 'Segoe UI', sans-serif";
      ctx.textBaseline = "middle";
      for (const it of items) {
        const y = it.y;
        ctx.fillStyle = it.colour;
        ctx.fillRect(chartArea.right + 6, y - 1, 8, 2);
        ctx.fillStyle = css("--muted");
        ctx.fillText(it.text, chartArea.right + 18, y);
      }
      ctx.restore();
    },
  };

  function makeChart(fig, name, series, t) {
    const labels = Object.keys(series);
    const cols = colours(name, labels);
    const stepped = fig.dataset.status === "1";
    const unit = fig.dataset.unit;
    return new Chart(fig.querySelector("canvas"), {
      type: "line",
      data: {
        datasets: labels.map((l, i) => ({
          label: l,
          data: t.map((x, j) => ({ x, y: series[l][j] })),
          borderColor: cols[i],
          backgroundColor: cols[i],
          borderWidth: 2,
          pointRadius: 0,
          pointHoverRadius: 4,
          pointHoverBorderWidth: 2,
          pointHoverBorderColor: css("--bg"),
          stepped: stepped,
          tension: 0,
        })),
      },
      plugins: [endLabels],
      options: {
        animation: false,
        maintainAspectRatio: false,
        layout: { padding: { right: 92 } },
        interaction: { mode: "index", intersect: false },
        scales: {
          x: {
            type: "linear",
            bounds: "data",
            min: t.length ? t[0] : undefined,
            max: t.length ? t[t.length - 1] : undefined,
            grid: { display: false },
            border: { color: css("--line") },
            ticks: { color: css("--muted"), maxTicksLimit: 6, callback: (v) => clock(v) },
          },
          y: {
            beginAtZero: true,
            grid: { color: css("--line") },
            border: { display: false },
            ticks: { color: css("--muted"), maxTicksLimit: 5, precision: stepped ? 0 : undefined,
                     callback: (v) => number(v) },
          },
        },
        plugins: {
          legend: {
            position: "top",
            align: "start",
            labels: { color: css("--muted"), boxWidth: 12, boxHeight: 2, font: { size: 12 } },
          },
          tooltip: {
            backgroundColor: css("--head"),
            borderColor: css("--line"),
            borderWidth: 1,
            titleColor: css("--fg"),
            bodyColor: css("--fg"),
            boxWidth: 8,
            boxHeight: 8,
            callbacks: {
              title: (items) => clock(items[0].parsed.x, true),
              label: (item) => " " + item.dataset.label + ": " + number(item.parsed.y) + " " + (stepped ? "" : unit),
            },
          },
        },
      },
    });
  }

  function table(fig, series, t) {
    const labels = Object.keys(series);
    const rows = t.map((x, j) =>
      "<tr><td>" + clock(x, true) + "</td>" + labels.map((l) => '<td class="r">' + number(series[l][j]) + "</td>").join("") + "</tr>");
    fig.querySelector(".table").innerHTML =
      "<table><thead><tr><th>Time</th>" + labels.map((l) => '<th class="r">' + l + "</th>").join("") +
      "</tr></thead><tbody>" + rows.reverse().join("") + "</tbody></table>";
  }

  function draw(data, rebuild) {
    document.getElementById("graphs-empty").hidden = data.t.length > 0;
    for (const fig of root.querySelectorAll("figure.chart")) {
      const name = fig.dataset.chart;
      const series = data[name];
      if (rebuild && charts[name]) {
        charts[name].destroy();
        delete charts[name];
      }
      if (!charts[name]) {
        charts[name] = makeChart(fig, name, series, data.t);
      } else {
        charts[name].data.datasets.forEach((ds) => {
          ds.data = data.t.map((x, j) => ({ x, y: series[ds.label][j] }));
        });
        charts[name].options.scales.x.min = data.t[0];
        charts[name].options.scales.x.max = data.t[data.t.length - 1];
        charts[name].update("none");
      }
      if (fig.querySelector("details").open) table(fig, series, data.t);
    }
  }

  let last = null;
  async function refresh(rebuild) {
    try {
      const r = await fetch("/api/history", { cache: "no-store" });
      last = await r.json();
      draw(last, rebuild);
    } catch (e) {
      console.warn("history fetch failed", e);
    }
  }

  for (const d of root.querySelectorAll("details")) {
    d.addEventListener("toggle", () => {
      if (d.open && last) {
        const fig = d.closest("figure");
        table(fig, last[fig.dataset.chart], last.t);
      }
    });
  }
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => last && draw(last, true));

  refresh(true);
  setInterval(() => refresh(false), interval * 1000);
})();
