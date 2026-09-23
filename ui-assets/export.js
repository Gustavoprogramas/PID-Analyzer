const { chromium } = require("playwright");
const path = require("path");
const fs = require("fs");
const { pathToFileURL } = require("url");

const outputDir = path.join(__dirname, "output");

const assets = [
  { selector: "#surface-card", file: "surface_card.png" },
  { selector: "#surface-console", file: "surface_console.png" },
  // Botões Start
  { selector: "#btn-start-normal", file: "btn_start_normal.png" },
  { selector: "#btn-start-hover", file: "btn_start_hover.png" },
  { selector: "#btn-start-pressed", file: "btn_start_pressed.png" },

  // Botões Stop
  { selector: "#btn-stop-normal", file: "btn_stop_normal.png" },
  { selector: "#btn-stop-hover", file: "btn_stop_hover.png" },
  { selector: "#btn-stop-pressed", file: "btn_stop_pressed.png" },

  // Botões Settings
  { selector: "#btn-settings-normal", file: "btn_settings_normal.png" },
  { selector: "#btn-settings-hover", file: "btn_settings_hover.png" },
  { selector: "#btn-settings-pressed", file: "btn_settings_pressed.png" },

  // Botões Export
  { selector: "#btn-export-normal", file: "btn_export_normal.png" },
  { selector: "#btn-export-hover", file: "btn_export_hover.png" },
  { selector: "#btn-export-pressed", file: "btn_export_pressed.png" },

  // Badges
  { selector: "#badge-low", file: "badge_low.png" },
  { selector: "#badge-attention", file: "badge_attention.png" },
  { selector: "#badge-suspicious", file: "badge_suspicious.png" },
  { selector: "#badge-highrisk", file: "badge_highrisk.png" },

  // Status dots
  { selector: "#status-dot-active", file: "status_dot_active.png" },
  { selector: "#status-dot-warning", file: "status_dot_warning.png" },
  { selector: "#status-dot-danger", file: "status_dot_danger.png" },
  { selector: "#status-dot-paused", file: "status_dot_paused.png" },

  // Cards
  { selector: "#card-status", file: "card_status.png" },
  { selector: "#card-alerts", file: "card_alerts.png" },
  { selector: "#card-risk", file: "card_risk.png" },

  // Outros componentes
  { selector: "#alert-card", file: "alert_card.png" },
  { selector: "#console-panel", file: "console_panel.png" },
  { selector: "#sidebar-panel", file: "sidebar_panel.png" },
  { selector: "#topbar-panel", file: "topbar_panel.png" },
  { selector: "#dashboard-preview", file: "dashboard_preview.png" }
];

(async () => {
  fs.mkdirSync(outputDir, { recursive: true });

  const browser = await chromium.launch({
    headless: true
  });

  const page = await browser.newPage({
    viewport: { width: 1800, height: 5000 },
    deviceScaleFactor: 2
  });

  const filePath = pathToFileURL(path.join(__dirname, "assets.html")).href;
  await page.goto(filePath);
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  await page.addStyleTag({ content: 'body { background: transparent !important; } .preview-group { background: transparent; border-color: transparent; box-shadow: none; }' });

  for (const asset of assets) {
    const locator = page.locator(asset.selector);
    await locator.scrollIntoViewIfNeeded();
    await locator.screenshot({
      path: path.join(outputDir, asset.file),
      omitBackground: true
    });
    console.log("Exportado:", asset.file);
  }

  await browser.close();
  // Incorpora apenas as artes usadas pela interface.
  const embedded = assets.filter(a => a.file.startsWith("btn_") || a.file.startsWith("badge_") || a.file.startsWith("status_dot_") || a.file.startsWith("surface_"));
  let header = "#pragma once\nnamespace UiAssets {\n";
  for (const asset of embedded) {
    const bytes = fs.readFileSync(path.join(outputDir, asset.file));
    const name = asset.file.replace(".png", "");
    header += `inline const unsigned char ${name}[] = {\n`;
    for (let i = 0; i < bytes.length; i += 24) header += Array.from(bytes.subarray(i, i + 24)).join(",") + ",\n";
    header += "};\n";
  }
  header += "}\n";
  fs.writeFileSync(path.join(__dirname, "embedded_assets.h"), header);
  console.log("\nFinalizado. Assets salvos em:", outputDir);
})().catch(error => { console.error(error); process.exitCode = 1; });
