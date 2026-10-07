/* KOBİ Tehdit İstihbaratı Portalı — istemci uygulaması
 * Bağımlılık yok. data/*.json dosyalarını okur, tüm işlemler tarayıcıda yapılır.
 * Kullanıcıya özel veriler (envanter, kontrol listesi) yalnızca localStorage'da tutulur.
 */
(() => {
  "use strict";

  // ------------------------------------------------------------------ yardımcılar
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const safeUrl = (u) => (/^https?:\/\//i.test(u || "") ? u : "");
  const link = (u, text, cls = "") => { const s = safeUrl(u); return s ? `<a href="${esc(s)}" target="_blank" rel="noopener noreferrer" class="${cls}">${esc(text)}</a>` : esc(text); };
  const norm = (s) => String(s || "").toLowerCase().replace(/İ/g, "i").replace(/ı/g, "i").normalize("NFKD").replace(/[̀-ͯ]/g, "").trim();
  const DAY = 864e5;
  const today = new Date();
  const daysSince = (d) => { const t = Date.parse(d); return isNaN(t) ? 9999 : Math.floor((today - t) / DAY); };
  const fmtDate = (d) => { const t = Date.parse(d); return isNaN(t) ? "—" : new Date(t).toLocaleDateString("tr-TR", { day: "2-digit", month: "short", year: "numeric" }); };
  const fmtDateTime = (d) => { const t = Date.parse(d); return isNaN(t) ? "—" : new Date(t).toLocaleString("tr-TR", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }); };
  const relTime = (d) => {
    const m = Math.round((today - Date.parse(d)) / 6e4);
    if (isNaN(m)) return "—";
    if (m < 60) return `${Math.max(m, 1)} dk önce`;
    if (m < 1440) return `${Math.round(m / 60)} saat önce`;
    return `${Math.round(m / 1440)} gün önce`;
  };
  const fmtNum = (n) => Number(n || 0).toLocaleString("tr-TR");
  const pct = (x) => `%${(x * 100).toLocaleString("tr-TR", { maximumFractionDigits: 1 })}`;

  const store = {
    get(k, def) { try { const v = localStorage.getItem("kobicti:" + k); return v ? JSON.parse(v) : def; } catch { return def; } },
    set(k, v) { try { localStorage.setItem("kobicti:" + k, JSON.stringify(v)); } catch { /* özel pencere vb. */ } },
  };

  function toast(msg) {
    const t = $("#toast"); t.textContent = msg; t.classList.add("show");
    clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove("show"), 2200);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast("Panoya kopyalandı"); }
    catch { toast("Kopyalanamadı; metni elle seçin"); }
  }
  function download(name, text, type = "text/plain") {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: type + ";charset=utf-8" }));
    a.download = name; document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }
  const csvCell = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;

  // ------------------------------------------------------------------ durum
  const S = {
    meta: null, kev: [], epss: {}, iocs: [], news: [], rw: [],
    assets: store.get("assets", []),
    checks: store.get("checks", {}),
    org: store.get("org", ""),
    ui: { kev: { q: "", vendor: "", mine: false, rw: false, recent: false, sort: "prio", dir: -1, limit: 50, open: null },
          news: { q: "", src: "", mine: false }, rwView: { scope: "local" } },
  };

  // ------------------------------------------------------------------ varlık eşleme ve önceliklendirme
  const PRESETS = [
    ["Fortinet", "FortiOS", "FortiGate güvenlik duvarı"], ["Microsoft", "Exchange", "E-posta sunucusu"],
    ["Microsoft", "Windows", "Windows istemci/sunucu"], ["Microsoft", "SharePoint", ""], ["Microsoft", "Office", ""],
    ["MikroTik", "RouterOS", "Yönlendirici"], ["Cisco", "IOS", "Anahtar/yönlendirici"], ["Cisco", "Adaptive Security Appliance", "ASA güvenlik duvarı"],
    ["SonicWall", "", "Güvenlik duvarı / VPN"], ["Zyxel", "", "Güvenlik duvarı / modem"], ["Sophos", "", "Güvenlik duvarı"],
    ["Check Point", "", "Güvenlik duvarı"], ["Palo Alto Networks", "PAN-OS", ""], ["Ivanti", "", "VPN / MDM"],
    ["Citrix", "", "NetScaler / uzak erişim"], ["VMware", "", "ESXi / vCenter"], ["Veeam", "", "Yedekleme"],
    ["Synology", "", "NAS"], ["QNAP", "", "NAS"], ["D-Link", "", "Ağ cihazı"], ["TP-Link", "", "Ağ cihazı"],
    ["Hikvision", "", "IP kamera / NVR"], ["Apache", "", "Web sunucu / Tomcat"], ["WordPress", "", "Web sitesi"],
    ["Google", "Chromium", "Tarayıcılar"], ["Atlassian", "", "Confluence / Jira"], ["Oracle", "", ""],
    ["Linux", "Kernel", ""], ["ConnectWise", "", "Uzak destek"], ["Progress", "", "MOVEit / Telerik"],
  ];

  function assetMatches(k) {
    const v = norm(k.vendor), p = norm(k.product);
    return S.assets.filter((a) => {
      if (!a.vendor) return false;
      if (!v.includes(norm(a.vendor))) return false;
      return !a.product || p.includes(norm(a.product));
    });
  }
  const epssOf = (cve) => (S.epss[cve] || [0, 0]);
  const newDays = () => (S.meta?.kev_new_days || 14);

  function enrichKev() {
    for (const k of S.kev) {
      const m = assetMatches(k);
      const [e] = epssOf(k.cve);
      k._mine = m.length > 0;
      k._assets = m;
      k._new = daysSince(k.added) <= newDays();
      k._epss = e;
      k._score = (k._mine ? 50 : 0) + (k.ransomware ? 20 : 0) + e * 25 + (k._new ? 10 : 0);
      k._prio = k._score >= 70 ? "kritik" : k._score >= 45 ? "yuksek" : k._score >= 20 ? "orta" : "dusuk";
    }
  }
  const PRIO_LABEL = { kritik: "Kritik", yuksek: "Yüksek", orta: "Orta", dusuk: "Düşük" };
  const prioTag = (p) => `<span class="prio ${p}">${PRIO_LABEL[p]}</span>`;

  function newsMatches(n) {
    const t = norm(n.title + " " + n.summary);
    return S.assets.filter((a) => {
      const term = norm(a.product || a.vendor);
      return term.length > 2 && t.includes(term);
    });
  }

  function threatLevel() {
    const recent = S.kev.filter((k) => daysSince(k.added) <= 30);
    const mine = recent.filter((k) => k._mine);
    const hot = mine.filter((k) => k.ransomware || k._epss >= 0.5);
    const newRw = S.kev.filter((k) => k._new && k.ransomware);
    if (!S.assets.length) {
      return {
        level: newRw.length ? "sari" : "yesil", noAssets: true,
        text: `Envanterinizi tanımlamadığınız için genel değerlendirme gösteriliyor. Son ${newDays()} günde ${S.kev.filter((k) => k._new).length} zafiyet aktif istismar listesine eklendi${newRw.length ? `, bunların ${newRw.length} tanesi fidye yazılımı saldırılarında kullanılıyor` : ""}.`,
      };
    }
    if (hot.length) return { level: "kirmizi", items: hot, text: `Envanterinizdeki ürünlerde son 30 günde ${hot.length} adet aktif istismar edilen ve yüksek riskli zafiyet var. Bugün yamalayın ya da erişimi kısıtlayın.` };
    if (mine.length) return { level: "turuncu", items: mine, text: `Envanterinizdeki ürünleri etkileyen ${mine.length} yeni aktif istismar kaydı var. Bu hafta içinde yama planlayın.` };
    if (newRw.length) return { level: "sari", text: `Envanterinizi doğrudan etkileyen yeni kayıt yok; ancak son ${newDays()} günde fidye yazılımı gruplarının kullandığı ${newRw.length} yeni zafiyet eklendi. Envanterinizin güncel olduğundan emin olun.` };
    return { level: "yesil", text: "Envanterinizi etkileyen yeni aktif istismar kaydı yok. Rutin yama ve yedekleme kontrollerine devam edin." };
  }
  const LEVEL_NAME = { yesil: "Yeşil", sari: "Sarı", turuncu: "Turuncu", kirmizi: "Kırmızı" };
  const LEVEL_ORDER = ["yesil", "sari", "turuncu", "kirmizi"];

  // ------------------------------------------------------------------ IOC dizinleri
  const IDX = { byVal: new Map(), byHost: new Map() };
  function refang(s) {
    return String(s).trim().replace(/^hxxp/i, "http").replace(/\[\.\]|\(\.\)|\{\.\}/g, ".").replace(/\[:\]/g, ":").replace(/\[\/\]/g, "/");
  }
  function hostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } }
  function buildIndex() {
    IDX.byVal.clear(); IDX.byHost.clear();
    const add = (m, k, x) => { if (!k) return; const a = m.get(k); a ? a.push(x) : m.set(k, [x]); };
    for (const x of S.iocs) {
      const v = x.t === "url" ? x.v.trim() : x.v.toLowerCase().trim();
      add(IDX.byVal, v, x);
      if (x.t === "url") add(IDX.byHost, hostOf(x.v), x);
    }
  }
  function detectType(v) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "ip";
    if (/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(v)) return "hash";
    if (/^https?:\/\//i.test(v)) return "url";
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return "domain";
    return "bilinmiyor";
  }
  function lookup(raw) {
    const v0 = refang(raw);
    const t = detectType(v0);
    const v = t === "url" ? v0 : v0.toLowerCase();
    const hits = new Set(IDX.byVal.get(v) || []);
    let host = "";
    if (t === "url") host = hostOf(v);
    if (t === "domain") host = v;
    if (host) {
      // alan adının kendisi ve üst alan adları
      const parts = host.split(".");
      for (let i = 0; i < parts.length - 1; i++) {
        const h = parts.slice(i).join(".");
        (IDX.byVal.get(h) || []).forEach((x) => hits.add(x));
        if (i === 0) (IDX.byHost.get(h) || []).forEach((x) => hits.add(x));
      }
    }
    return { input: raw, value: v, type: t, hits: [...hits] };
  }
  function pivots(v, t) {
    const e = encodeURIComponent(v);
    const L = [["VirusTotal", `https://www.virustotal.com/gui/search/${e}`]];
    if (t === "ip") L.push(["AbuseIPDB", `https://www.abuseipdb.com/check/${e}`], ["Shodan", `https://www.shodan.io/host/${e}`], ["GreyNoise", `https://viz.greynoise.io/ip/${e}`]);
    if (t === "domain" || t === "url") L.push(["urlscan.io", `https://urlscan.io/search/#${e}`]);
    if (t === "hash") L.push(["MalwareBazaar", `https://bazaar.abuse.ch/browse.php?search=${e}`]);
    L.push(["ThreatFox", `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e}`]);
    return L.map(([n, u]) => link(u, n)).join("");
  }

  // ------------------------------------------------------------------ görünümler
  const VIEWS = {};
  const main = () => $("#main");

  // ---------- Genel bakış
  VIEWS.genel = () => {
    const lv = threatLevel();
    const idx = LEVEL_ORDER.indexOf(lv.level);
    const newKev = S.kev.filter((k) => k._new);
    const mine30 = S.kev.filter((k) => k._mine && daysSince(k.added) <= 30);
    const bl = S.meta?.blocklists || {};
    const cc = S.meta?.ransomware_country || "TR";
    const rwLocal = S.rw.filter((r) => r.country === cc && daysSince(r.date) <= 30);
    const top = [...S.kev].sort((a, b) => b._score - a._score).slice(0, 6);
    const news = S.news.slice(0, 6);

    main().innerHTML = `
      <section class="alert-band" data-level="${lv.level}" aria-label="Tehdit uyarı seviyesi">
        <div class="alert-scale" aria-hidden="true">${LEVEL_ORDER.slice().reverse().map((l, i) => `<span class="${3 - i <= idx ? "on" : ""}"></span>`).join("")}</div>
        <div>
          <p class="alert-level">${LEVEL_NAME[lv.level]} uyarı</p>
          <p class="alert-text">${esc(lv.text)}</p>
          <div class="alert-actions">
            ${lv.noAssets ? `<a class="btn" href="#varliklar">Envanterimi tanımla</a>` : `<a class="btn" href="#zafiyetler?mine=1">Etkilenen ürünleri gör</a>`}
            <a class="btn ghost" href="#bulten">Haftalık bülteni hazırla</a>
          </div>
        </div>
      </section>

      <div class="figures">
        <div class="figure"><a href="#zafiyetler?recent=1"><b>${fmtNum(newKev.length)}</b><span>Son ${newDays()} günde aktif istismar listesine eklenen zafiyet</span></a></div>
        <div class="figure"><a href="#zafiyetler?mine=1"><b>${S.assets.length ? fmtNum(mine30.length) : "—"}</b><span>${S.assets.length ? "Envanterinizi etkileyen kayıt (30 gün)" : "Envanter tanımlanmadı"}</span></a></div>
        <div class="figure"><a href="#engelleme"><b>${fmtNum((bl.ip || 0) + (bl.domain || 0))}</b><span>Engelleme listesindeki IP ve alan adı</span></a></div>
        <div class="figure"><a href="#fidye"><b>${fmtNum(rwLocal.length)}</b><span>${esc(cc)} kaynaklı fidye yazılımı mağduru (30 gün)</span></a></div>
      </div>

      <div class="grid-2">
        <section class="panel">
          <div class="panel-head"><h2>Öncelikli işler</h2><a href="#zafiyetler">Tüm zafiyetler</a></div>
          ${top.length ? `<ul class="list">${top.map((k) => `
            <li class="task">${prioTag(k._prio)}
              <div><a class="row-title" href="#zafiyetler?cve=${esc(k.cve)}">${esc(k.vendor)} ${esc(k.product)}</a>
                <div class="row-meta"><span class="cve">${esc(k.cve)}</span><span>${fmtDate(k.added)}</span>
                ${k._mine ? `<span class="tag mine">Envanterimde</span>` : ""}${k.ransomware ? `<span class="tag rw">Fidye yazılımı</span>` : ""}
                ${k._epss ? `<span>EPSS ${pct(k._epss)}</span>` : ""}</div></div></li>`).join("")}</ul>`
            : `<div class="empty"><strong>Zafiyet verisi yok</strong>Kaynaklar sayfasından veri durumunu kontrol edin.</div>`}
        </section>
        <section class="panel">
          <div class="panel-head"><h2>Son haberler</h2><a href="#haberler">Tümü</a></div>
          ${news.length ? `<ul class="list">${news.map(newsLi).join("")}</ul>` : `<div class="empty">Haber yok.</div>`}
        </section>
      </div>

      <section class="panel" style="margin-top:20px">
        <div class="panel-head"><h2>Haftalık aktif istismar eklemeleri</h2><span class="small muted">Son 16 hafta · CISA KEV</span></div>
        <div class="chart">${weeklyChart()}</div>
        <div class="legend"><span><i style="background:var(--accent)"></i>Tüm eklemeler</span><span><i style="background:var(--p-kritik)"></i>Fidye yazılımıyla ilişkili</span></div>
      </section>`;
  };

  function newsLi(n) {
    const m = newsMatches(n);
    const kevSet = new Set(S.kev.map((k) => k.cve));
    const kevHit = (n.cves || []).some((c) => kevSet.has(c));
    return `<li class="news-item">${link(n.link, n.title, "row-title")}
      <div class="row-meta"><span>${esc(n.source)}</span><span>${relTime(n.date)}</span>
      ${m.length ? `<span class="tag mine">${esc(m[0].vendor)}</span>` : ""}${kevHit ? `<span class="tag rw">KEV'de</span>` : ""}
      ${(n.cves || []).slice(0, 3).map((c) => `<span class="cve">${esc(c)}</span>`).join("")}</div></li>`;
  }

  function weeklyChart() {
    const W = 16, w = Math.max(300, Math.round((main().clientWidth || 720) - 48)), h = w < 500 ? 150 : 190, pad = { l: 28, r: 6, t: 10, b: 24 };
    const start = new Date(today); start.setHours(0, 0, 0, 0);
    start.setDate(start.getDate() - ((start.getDay() + 6) % 7)); // pazartesi
    const weeks = Array.from({ length: W }, (_, i) => { const d = new Date(start); d.setDate(d.getDate() - (W - 1 - i) * 7); return { d, all: 0, rw: 0 }; });
    for (const k of S.kev) {
      const t = Date.parse(k.added); if (isNaN(t)) continue;
      const wi = t >= start ? W - 1 : W - 1 - Math.ceil((start - t) / (7 * DAY));
      if (wi < 0 || wi >= W) continue;
      weeks[wi].all++; if (k.ransomware) weeks[wi].rw++;
    }
    const max = Math.max(4, ...weeks.map((x) => x.all));
    const cw = (w - pad.l - pad.r) / W, bh = h - pad.t - pad.b;
    let s = `<svg viewBox="0 0 ${w} ${h}" role="img" aria-label="Son ${W} haftada CISA KEV kataloğuna eklenen zafiyet sayıları">`;
    for (const g of [0, Math.round(max / 2), max]) {
      const y = pad.t + bh - (g / max) * bh;
      s += `<line class="axis" x1="${pad.l}" x2="${w - pad.r}" y1="${y}" y2="${y}"/><text x="${pad.l - 6}" y="${y + 4}" text-anchor="end">${g}</text>`;
    }
    weeks.forEach((x, i) => {
      const x0 = pad.l + i * cw + 3, bw = cw - 6;
      const ha = (x.all / max) * bh, hr = (x.rw / max) * bh;
      s += `<rect class="bar" x="${x0}" y="${pad.t + bh - ha}" width="${bw}" height="${ha}" rx="2"><title>${x.d.toLocaleDateString("tr-TR")} haftası: ${x.all} ekleme, ${x.rw} fidye yazılımı</title></rect>`;
      if (hr) s += `<rect class="bar rw" x="${x0}" y="${pad.t + bh - hr}" width="${bw}" height="${hr}" rx="2"/>`;
      if (i % (w < 500 ? 5 : 3) === 0 || i === W - 1) s += `<text x="${x0 + bw / 2}" y="${h - 6}" text-anchor="middle">${x.d.toLocaleDateString("tr-TR", { day: "2-digit", month: "short" })}</text>`;
    });
    return s + "</svg>";
  }

  // ---------- Zafiyetler
  VIEWS.zafiyetler = (params) => {
    const u = S.ui.kev;
    if (params.has("mine")) { u.mine = true; u.recent = false; }
    if (params.has("recent")) { u.recent = true; u.mine = false; }
    if (params.has("cve")) { u.q = params.get("cve"); u.open = params.get("cve"); u.mine = u.recent = u.rw = false; }
    const vendors = [...new Set(S.kev.map((k) => k.vendor))].sort((a, b) => a.localeCompare(b, "tr"));
    main().innerHTML = `
      <div class="page-head"><div><h1>Aktif istismar edilen zafiyetler</h1>
        <p>CISA KEV kataloğundaki ${fmtNum(S.kev.length)} kayıt; envanterinize, fidye yazılımı kullanımına ve EPSS olasılığına göre önceliklendirildi.</p></div>
        <button class="btn subtle" id="kev-csv" type="button">CSV indir</button></div>
      <div class="toolbar">
        <input type="search" id="kev-q" placeholder="CVE, üretici veya ürün ara" value="${esc(u.q)}" aria-label="Zafiyet ara">
        <select id="kev-vendor" aria-label="Üretici"><option value="">Tüm üreticiler</option>${vendors.map((v) => `<option ${v === u.vendor ? "selected" : ""}>${esc(v)}</option>`).join("")}</select>
        <label class="check"><input type="checkbox" id="kev-mine" ${u.mine ? "checked" : ""}> Yalnızca envanterim</label>
        <label class="check"><input type="checkbox" id="kev-rw" ${u.rw ? "checked" : ""}> Fidye yazılımıyla ilişkili</label>
        <label class="check"><input type="checkbox" id="kev-recent" ${u.recent ? "checked" : ""}> Son ${newDays()} gün</label>
      </div>
      <div id="kev-table"></div>`;
    const re = () => renderKevTable();
    $("#kev-q").addEventListener("input", (e) => { u.q = e.target.value; u.limit = 50; re(); });
    $("#kev-vendor").addEventListener("change", (e) => { u.vendor = e.target.value; u.limit = 50; re(); });
    $("#kev-mine").addEventListener("change", (e) => { u.mine = e.target.checked; re(); });
    $("#kev-rw").addEventListener("change", (e) => { u.rw = e.target.checked; re(); });
    $("#kev-recent").addEventListener("change", (e) => { u.recent = e.target.checked; re(); });
    $("#kev-csv").addEventListener("click", () => {
      const rows = filteredKev();
      const head = ["Öncelik", "CVE", "Üretici", "Ürün", "Ad", "Eklenme", "CISA son tarih", "EPSS", "Fidye yazılımı", "Envanter", "Gerekli aksiyon"];
      const body = rows.map((k) => [PRIO_LABEL[k._prio], k.cve, k.vendor, k.product, k.name, k.added, k.due, k._epss, k.ransomware ? "Evet" : "Hayır", k._assets.map((a) => a.vendor + " " + a.product).join("; "), k.action]);
      download(`kev-${new Date().toISOString().slice(0, 10)}.csv`, "﻿" + [head, ...body].map((r) => r.map(csvCell).join(";")).join("\r\n"), "text/csv");
    });
    re();
    if (u.open) setTimeout(() => $(`tr[data-cve="${CSS.escape(u.open)}"]`)?.scrollIntoView({ block: "center" }), 50);
  };

  function filteredKev() {
    const u = S.ui.kev, q = norm(u.q);
    let r = S.kev.filter((k) =>
      (!q || norm(`${k.cve} ${k.vendor} ${k.product} ${k.name}`).includes(q)) &&
      (!u.vendor || k.vendor === u.vendor) && (!u.mine || k._mine) && (!u.rw || k.ransomware) && (!u.recent || k._new));
    const key = { prio: (k) => k._score, cve: (k) => k.cve, vendor: (k) => k.vendor + k.product, added: (k) => k.added, due: (k) => k.due, epss: (k) => k._epss }[u.sort];
    r.sort((a, b) => { const x = key(a), y = key(b); return (x > y ? 1 : x < y ? -1 : 0) * u.dir; });
    return r;
  }

  function renderKevTable() {
    const u = S.ui.kev, rows = filteredKev(), shown = rows.slice(0, u.limit);
    const col = (k, label, cls = "") => `<th class="${cls}" aria-sort="${u.sort === k ? (u.dir < 0 ? "descending" : "ascending") : "none"}"><button data-sort="${k}">${label}</button></th>`;
    const el = $("#kev-table");
    if (!rows.length) {
      el.innerHTML = `<div class="table-wrap"><div class="empty"><strong>Filtrelere uyan kayıt yok</strong>${u.mine && !S.assets.length ? `Önce <a href="#varliklar">envanterinizi tanımlayın</a>.` : "Filtreleri gevşetmeyi deneyin."}</div></div>`;
      return;
    }
    el.innerHTML = `<div class="table-wrap"><table>
      <thead><tr>${col("prio", "Öncelik")}${col("cve", "CVE")}${col("vendor", "Üretici / ürün")}${col("added", "Eklenme")}${col("epss", "EPSS", "num")}<th>Durum</th></tr></thead>
      <tbody>${shown.map((k) => `
        <tr class="kev-row ${u.open === k.cve ? "open" : ""}" data-cve="${esc(k.cve)}" tabindex="0" aria-expanded="${u.open === k.cve}">
          <td>${prioTag(k._prio)}</td><td class="cve">${esc(k.cve)}</td>
          <td><strong>${esc(k.vendor)}</strong> ${esc(k.product)}<div class="small muted">${esc(k.name)}</div></td>
          <td style="white-space:nowrap">${fmtDate(k.added)}</td>
          <td class="num">${k._epss ? pct(k._epss) + `<span class="epss-bar"><i style="width:${Math.round(k._epss * 100)}%"></i></span>` : "—"}</td>
          <td>${k._mine ? `<span class="tag mine">Envanterimde</span> ` : ""}${k.ransomware ? `<span class="tag rw">Fidye</span> ` : ""}${k._new ? `<span class="tag new">Yeni</span>` : ""}</td>
        </tr>${u.open === k.cve ? kevDetail(k) : ""}`).join("")}</tbody></table></div>
      ${rows.length > u.limit ? `<div class="more"><button class="btn subtle" id="kev-more">${fmtNum(rows.length - u.limit)} kayıt daha göster</button></div>` : `<p class="small muted" style="margin-top:10px">${fmtNum(rows.length)} kayıt gösteriliyor.</p>`}`;
    $$("th button", el).forEach((b) => b.addEventListener("click", () => {
      const s = b.dataset.sort; if (u.sort === s) u.dir *= -1; else { u.sort = s; u.dir = s === "cve" || s === "vendor" ? 1 : -1; }
      renderKevTable();
    }));
    $$("tr.kev-row", el).forEach((tr) => {
      const t = () => { u.open = u.open === tr.dataset.cve ? null : tr.dataset.cve; renderKevTable(); $(`tr[data-cve="${CSS.escape(tr.dataset.cve)}"]`)?.focus(); };
      tr.addEventListener("click", (e) => { if (!e.target.closest("a")) t(); });
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); t(); } });
    });
    $("#kev-more")?.addEventListener("click", () => { u.limit += 100; renderKevTable(); });
  }

  function kevDetail(k) {
    const [e, p] = epssOf(k.cve);
    return `<tr class="detail"><td colspan="6"><div class="detail-grid">
      <div><h4>Açıklama</h4><p>${esc(k.desc)}</p>
        <h4>Gerekli aksiyon (CISA)</h4><p>${esc(k.action)}</p>
        ${k._assets.length ? `<h4>Etkilenen envanter kalemleri</h4><p>${k._assets.map((a) => esc(`${a.vendor} ${a.product}`.trim()) + (a.note ? ` <span class="muted">(${esc(a.note)})</span>` : "")).join(", ")}</p>` : ""}</div>
      <div><h4>Ayrıntılar</h4>
        <p class="small">CISA son tarih: ${fmtDate(k.due)}<br>EPSS: ${e ? `${pct(e)} (yüzdelik ${pct(p)})` : "—"}<br>Fidye yazılımı kullanımı: ${k.ransomware ? "Biliniyor" : "Bilinmiyor"}${k.cwes?.length ? `<br>CWE: ${esc(k.cwes.join(", "))}` : ""}</p>
        <h4>Bağlantılar</h4><p class="pivots">
          ${link(`https://nvd.nist.gov/vuln/detail/${k.cve}`, "NVD")}
          ${link(`https://www.cve.org/CVERecord?id=${k.cve}`, "CVE.org")}
          ${link(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${k.cve}`, "CISA KEV")}
          ${(k.notes || []).slice(0, 3).map((n, i) => link(n, `Kaynak ${i + 1}`)).join("")}</p></div>
    </div></td></tr>`;
  }

  // ---------- Varlıklarım
  VIEWS.varliklar = () => {
    const pressed = (v, p) => S.assets.some((a) => norm(a.vendor) === norm(v) && norm(a.product) === norm(p));
    main().innerHTML = `
      <div class="page-head"><div><h1>Varlıklarım</h1>
        <p>Kullandığınız üretici ve ürünleri ekleyin; portal aktif istismar edilen zafiyetleri ve haberleri bu listeye göre işaretler. Liste yalnızca bu tarayıcıda saklanır.</p></div></div>
      <section class="panel">
        <h2>Ürün ekle</h2>
        <form class="asset-form" id="asset-form" autocomplete="off">
          <label>Üretici<input type="text" name="vendor" required placeholder="ör. Fortinet"></label>
          <label>Ürün (boş bırakılırsa üreticinin tüm ürünleri)<input type="text" name="product" placeholder="ör. FortiOS"></label>
          <label>Not<input type="text" name="note" placeholder="ör. Merkez ofis FW, v7.2.8"></label>
          <button class="btn" type="submit">Ekle</button>
        </form>
        <p class="small muted" style="margin:12px 0 0">KOBİ'lerde sık kullanılan ürünler — eklemek ya da çıkarmak için tıklayın:</p>
        <div class="presets">${PRESETS.map(([v, p, n]) => `<button type="button" class="chip" data-v="${esc(v)}" data-p="${esc(p)}" data-n="${esc(n)}" aria-pressed="${pressed(v, p)}">${esc(v)}${p ? " " + esc(p) : ""}</button>`).join("")}</div>
      </section>
      <section class="panel">
        <div class="panel-head"><h2>Envanter (${S.assets.length})</h2>
          <div class="toolbar" style="margin:0">
            <button class="btn subtle" type="button" id="as-export">Dışa aktar</button>
            <label class="btn subtle" style="cursor:pointer">İçe aktar<input type="file" id="as-import" accept="application/json" hidden></label>
            ${S.assets.length ? `<button class="btn danger" type="button" id="as-clear">Tümünü sil</button>` : ""}
          </div></div>
        ${S.assets.length ? `<div class="table-wrap"><table><thead><tr><th>Üretici</th><th>Ürün</th><th>Not</th><th class="num">Aktif istismar</th><th class="num">Son 30 gün</th><th></th></tr></thead><tbody>
          ${S.assets.map((a, i) => {
            const ks = S.kev.filter((k) => k._assets.includes(a));
            const r = ks.filter((k) => daysSince(k.added) <= 30).length;
            return `<tr><td><strong>${esc(a.vendor)}</strong></td><td>${esc(a.product) || `<span class="muted">tüm ürünler</span>`}</td><td>${esc(a.note)}</td>
              <td class="num"><a href="#zafiyetler?mine=1" class="match-count">${ks.length}</a></td><td class="num"><span class="match-count ${r ? "hot" : ""}">${r}</span></td>
              <td class="num"><button class="btn danger" data-del="${i}" type="button" aria-label="${esc(a.vendor)} sil">Sil</button></td></tr>`;
          }).join("")}</tbody></table></div>`
        : `<div class="empty"><strong>Envanter boş</strong>Yukarıdan ürün ekleyin. Envanter olmadan uyarı seviyesi yalnızca genel tehdit tablosunu yansıtır.</div>`}
        <p class="small muted" style="margin-top:12px">Eşleştirme, CISA KEV'deki üretici ve ürün adları üzerinden yapılır (ör. "Microsoft" + "Exchange"). Sürüm bilgisi değerlendirilmez; eşleşen her kaydı kendi sürümünüzle karşılaştırın.</p>
      </section>`;
    const save = () => { store.set("assets", S.assets); enrichKev(); VIEWS.varliklar(); };
    $("#asset-form").addEventListener("submit", (e) => {
      e.preventDefault(); const f = new FormData(e.target);
      const a = { vendor: f.get("vendor").trim(), product: f.get("product").trim(), note: f.get("note").trim() };
      if (!a.vendor) return;
      S.assets.push(a); save(); toast(`${a.vendor} eklendi`);
    });
    $$(".chip").forEach((c) => c.addEventListener("click", () => {
      const { v, p, n } = c.dataset;
      const i = S.assets.findIndex((a) => norm(a.vendor) === norm(v) && norm(a.product) === norm(p));
      if (i >= 0) S.assets.splice(i, 1); else S.assets.push({ vendor: v, product: p, note: n });
      save();
    }));
    $$("[data-del]").forEach((b) => b.addEventListener("click", () => { S.assets.splice(+b.dataset.del, 1); save(); }));
    $("#as-clear")?.addEventListener("click", () => { if (confirm("Tüm envanter silinsin mi?")) { S.assets = []; save(); } });
    $("#as-export").addEventListener("click", () => download("kobi-cti-envanter.json", JSON.stringify(S.assets, null, 2), "application/json"));
    $("#as-import").addEventListener("change", async (e) => {
      try {
        const arr = JSON.parse(await e.target.files[0].text());
        if (!Array.isArray(arr)) throw 0;
        S.assets = arr.filter((a) => a && a.vendor).map((a) => ({ vendor: String(a.vendor), product: String(a.product || ""), note: String(a.note || "") }));
        save(); toast(`${S.assets.length} kalem içe aktarıldı`);
      } catch { toast("Dosya okunamadı: geçerli bir envanter JSON'u seçin"); }
    });
  };

  // ---------- IOC arama
  VIEWS.ioc = () => {
    const by = {}; S.iocs.forEach((x) => (by[x.s] = (by[x.s] || 0) + 1));
    main().innerHTML = `
      <div class="page-head"><div><h1>IOC arama</h1>
        <p>Güvenlik duvarı, proxy veya e-posta kayıtlarınızdaki IP, alan adı, URL ve dosya özetlerini (hash) yapıştırın. Arama tamamen tarayıcınızda yapılır; değerler hiçbir yere gönderilmez.</p></div></div>
      <section class="panel">
        <textarea id="ioc-in" rows="7" placeholder="185.220.101.4&#10;kargo-takip[.]xyz&#10;hxxp://ornek[.]com/fatura.zip&#10;44d88612fea8a8f36de82e1278abb02f"></textarea>
        <div class="toolbar" style="margin:12px 0 0">
          <button class="btn" id="ioc-go" type="button">Ara</button>
          <button class="btn subtle" id="ioc-clear" type="button">Temizle</button>
          <span class="spacer"></span>
          <span class="small muted">Dizinde ${fmtNum(S.iocs.length)} gösterge: ${Object.entries(by).map(([k, v]) => `${esc(k)} ${fmtNum(v)}`).join(", ")}</span>
        </div>
      </section>
      <div id="ioc-out" style="margin-top:20px"></div>`;
    const run = () => {
      const lines = [...new Set($("#ioc-in").value.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean))].slice(0, 500);
      if (!lines.length) { $("#ioc-out").innerHTML = ""; return; }
      const res = lines.map(lookup);
      const hits = res.filter((r) => r.hits.length).length;
      $("#ioc-out").innerHTML = `
        <p><strong>${hits}</strong> / ${res.length} değer tehdit kaynaklarında bulundu.${hits ? " Eşleşen sistemleri inceleyin ve gerekirse ağdan izole edin." : " Eşleşme olmaması değerin güvenli olduğu anlamına gelmez; dış kaynaklarda da kontrol edin."}</p>
        <div class="table-wrap"><table><thead><tr><th>Değer</th><th>Tür</th><th>Sonuç</th><th>Dış kaynaklarda incele</th></tr></thead><tbody>
        ${res.map((r) => `<tr class="ioc-result ${r.hits.length ? "hit" : "miss"}"><td class="cve" style="white-space:normal;word-break:break-all">${esc(r.value)}</td><td>${esc(r.type)}</td>
          <td>${r.hits.length ? r.hits.slice(0, 4).map((h) => `<div><strong>${esc(h.s)}</strong> · ${esc(h.m || "zararlı")} ${h.d ? `<span class="muted small">(${fmtDate(h.d)})</span>` : ""} ${h.ref ? link(h.ref, "kayıt") : ""}${h.v !== r.value ? `<div class="small muted">eşleşen: ${esc(h.v)}</div>` : ""}</div>`).join("") : `<span class="muted">Kaynaklarda yok</span>`}</td>
          <td><div class="pivots">${r.type === "bilinmiyor" ? "" : pivots(r.value, r.type)}</div></td></tr>`).join("")}
        </tbody></table></div>`;
    };
    $("#ioc-go").addEventListener("click", run);
    $("#ioc-in").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) run(); });
    $("#ioc-clear").addEventListener("click", () => { $("#ioc-in").value = ""; $("#ioc-out").innerHTML = ""; });
  };

  // ---------- Engelleme listeleri
  VIEWS.engelleme = () => {
    const bl = S.meta?.blocklists || {};
    const abs = (p) => new URL(p, location.href.split("#")[0]).href;
    const feeds = [
      ["feeds/ip-blocklist.txt", "IP adresleri", bl.ip, "Aktif botnet C2 sunucuları ve zararlı IP'ler (Feodo Tracker, ThreatFox, USOM). Güvenlik duvarında hem giden hem gelen trafik için kullanın."],
      ["feeds/domain-blocklist.txt", "Alan adları", bl.domain, "C2 ve oltalama alan adları (ThreatFox, USOM). DNS filtresi veya web filtresi için uygundur. Büyük bulut ve kamu alan adları otomatik olarak hariç tutulur."],
      ["feeds/url-blocklist.txt", "URL'ler", bl.url, "Zararlı yazılım dağıtan, hâlâ erişilebilir URL'ler (URLhaus). Proxy veya web filtresi için."],
      ["feeds/mikrotik-blocklist.rsc", "MikroTik betiği", bl.ip, "IP listesinin RouterOS adres listesine dönüştürülmüş hâli; kayıtlar 2 gün sonra kendiliğinden düşer."],
    ];
    const ipUrl = abs("feeds/ip-blocklist.txt"), rscUrl = abs("feeds/mikrotik-blocklist.rsc"), domUrl = abs("feeds/domain-blocklist.txt");
    main().innerHTML = `
      <div class="page-head"><div><h1>Engelleme listeleri</h1>
        <p>Liste dosyaları bu sitede her güncellemede yeniden üretilir. Güvenlik duvarınıza adres olarak tanımlarsanız cihaz listeyi kendisi çeker.</p></div></div>
      <div class="note">Önce izleme (yalnızca kayıt) modunda bir hafta çalıştırın. Hatalı pozitif görürseniz alan adını <code>config.json</code> içindeki <code>blocklist_allow</code> listesine ekleyin.</div>
      <section class="panel">
        ${feeds.map(([p, n, c, d]) => `<div class="feed-row"><div><h3 style="margin:0 0 2px">${esc(n)} <span class="muted small">${fmtNum(c)} kayıt</span></h3><p class="small muted" style="margin:0 0 4px">${esc(d)}</p><div class="feed-url">${esc(abs(p))}</div></div>
          <div class="toolbar" style="margin:0"><button class="btn subtle" data-copy="${esc(abs(p))}" type="button">Adresi kopyala</button><a class="btn ghost" href="${esc(p)}" download>İndir</a></div></div>`).join("")}
      </section>
      <section class="panel howto">
        <h2>Cihazınıza tanımlama</h2>
        <details><summary>FortiGate (Threat Feed)</summary>
          <p>Security Fabric › External Connectors › Create New › Threat Feeds › <strong>IP Address</strong>. URI alanına aşağıdaki adresi girin, yenileme süresini 240 dakika yapın. Ardından bu bağlayıcıyı güvenlik duvarı ilkesinde hedef adres olarak kullanın. Alan adı listesi için <strong>Domain Name</strong> türünde ikinci bir bağlayıcı oluşturup DNS filtresinde engelleyin.</p>
          <pre>${esc(ipUrl)}\n${esc(domUrl)}</pre></details>
        <details><summary>MikroTik RouterOS</summary>
          <p>Aşağıdaki betik 4 saatte bir listeyi indirir ve içe aktarır. Engelleme kurallarını bir kez ekleyin.</p>
<pre>/system script add name=kobi-cti source={
  /tool fetch url="${esc(rscUrl)}" dst-path=kobi-cti.rsc
  :delay 3s
  /import file-name=kobi-cti.rsc
}
/system scheduler add name=kobi-cti interval=4h on-event=kobi-cti start-time=startup
/ip firewall raw add chain=prerouting src-address-list=kobi-cti action=drop comment="kobi-cti gelen"
/ip firewall raw add chain=prerouting dst-address-list=kobi-cti action=drop comment="kobi-cti giden"</pre></details>
        <details><summary>pfSense / OPNsense</summary>
          <p>pfSense'te pfBlockerNG › IP › IPv4 altında yeni bir liste ekleyip kaynak olarak IP adresini girin; DNSBL bölümüne alan adı listesini ekleyin. OPNsense'te Firewall › Aliases altında <strong>URL Table (IPs)</strong> türünde bir takma ad oluşturup engelleme kuralında kullanın.</p>
          <pre>${esc(ipUrl)}</pre></details>
        <details><summary>Sophos, Palo Alto, Check Point ve diğerleri</summary>
          <p>Çoğu yeni nesil güvenlik duvarı "External Dynamic List", "Threat Feed" veya "IP List from URL" adıyla düz metin liste desteği sunar. Dosyalar her satırda bir kayıt içerir; <code>#</code> ile başlayan satırlar açıklamadır.</p></details>
        <details><summary>Windows DNS / Pi-hole / AdGuard Home</summary>
          <p>Pi-hole ve AdGuard Home'da alan adı listesini doğrudan "adlist" olarak ekleyebilirsiniz. Windows DNS sunucusu için listeyi PowerShell ile <code>Add-DnsServerQueryResolutionPolicy</code> kurallarına dönüştürmeniz gerekir.</p>
          <pre>${esc(domUrl)}</pre></details>
      </section>`;
    $$("[data-copy]").forEach((b) => b.addEventListener("click", () => copy(b.dataset.copy)));
  };

  // ---------- Haberler
  VIEWS.haberler = () => {
    const u = S.ui.news;
    const srcs = [...new Set(S.news.map((n) => n.source))].sort();
    main().innerHTML = `
      <div class="page-head"><div><h1>Güvenlik haberleri</h1><p>Seçili kaynaklardan son ${S.meta?.news_days || 14} günün başlıkları. Envanterinizle ilgili olanlar ve CISA KEV'de yer alan CVE'ler işaretlenir.</p></div></div>
      <div class="toolbar">
        <input type="search" id="n-q" placeholder="Başlıkta ara" value="${esc(u.q)}" aria-label="Haber ara">
        <select id="n-src" aria-label="Kaynak"><option value="">Tüm kaynaklar</option>${srcs.map((s) => `<option ${s === u.src ? "selected" : ""}>${esc(s)}</option>`).join("")}</select>
        <label class="check"><input type="checkbox" id="n-mine" ${u.mine ? "checked" : ""}> Envanterimle ilgili</label>
      </div>
      <section class="panel"><ul class="list" id="n-list"></ul></section>`;
    const re = () => {
      const q = norm(u.q);
      const r = S.news.filter((n) => (!q || norm(n.title + " " + n.summary).includes(q)) && (!u.src || n.source === u.src) && (!u.mine || newsMatches(n).length));
      $("#n-list").innerHTML = r.length ? r.map((n) => newsLi(n).replace("</li>", n.summary ? `<p class="small muted" style="margin:6px 0 0">${esc(n.summary)}</p></li>` : "</li>")).join("")
        : `<li class="empty"><strong>Haber bulunamadı</strong>${u.mine && !S.assets.length ? "Envanteriniz boş." : "Filtreleri değiştirin."}</li>`;
    };
    $("#n-q").addEventListener("input", (e) => { u.q = e.target.value; re(); });
    $("#n-src").addEventListener("change", (e) => { u.src = e.target.value; re(); });
    $("#n-mine").addEventListener("change", (e) => { u.mine = e.target.checked; re(); });
    re();
  };

  // ---------- Fidye yazılımı
  VIEWS.fidye = () => {
    const cc = S.meta?.ransomware_country || "TR";
    const v = S.ui.rwView;
    const scope = v.scope === "local" ? S.rw.filter((r) => r.country === cc) : S.rw;
    const last30 = scope.filter((r) => daysSince(r.date) <= 30);
    const count = (arr, key) => Object.entries(arr.reduce((m, r) => { const k = r[key] || "Belirtilmemiş"; m[k] = (m[k] || 0) + 1; return m; }, {})).sort((a, b) => b[1] - a[1]);
    const bars = (pairs) => { const max = Math.max(1, ...pairs.map((p) => p[1])); return pairs.length ? `<ul class="hbars">${pairs.slice(0, 10).map(([k, n]) => `<li><span class="lbl" title="${esc(k)}">${esc(k)}</span><span class="track"><span class="fill" style="display:block;width:${(n / max) * 100}%"></span></span><span class="val">${n}</span></li>`).join("")}</ul>` : `<p class="muted">Kayıt yok.</p>`; };
    main().innerHTML = `
      <div class="page-head"><div><h1>Fidye yazılımı takibi</h1>
        <p>Fidye yazılımı gruplarının sızıntı sitelerinde duyurduğu mağdurlar (ransomware.live). Hangi grupların ve sektörlerin hedeflendiğini görmek için kullanın.</p></div>
        <div class="toolbar" style="margin:0" role="group" aria-label="Kapsam">
          <button class="chip" data-scope="local" aria-pressed="${v.scope === "local"}">${esc(cc)}</button>
          <button class="chip" data-scope="all" aria-pressed="${v.scope === "all"}">Tüm dünya</button></div></div>
      <div class="figures">
        <div class="figure"><b>${fmtNum(last30.length)}</b><span>Son 30 günde mağdur</span></div>
        <div class="figure"><b>${fmtNum(new Set(last30.map((r) => r.group)).size)}</b><span>Aktif grup (30 gün)</span></div>
        <div class="figure"><b>${esc(count(last30, "group")[0]?.[0] || "—")}</b><span>En aktif grup</span></div>
        <div class="figure"><b>${esc(count(last30, "sector")[0]?.[0] || "—")}</b><span>En çok hedeflenen sektör</span></div>
      </div>
      <div class="grid-2">
        <section class="panel"><h2>Gruplar (30 gün)</h2>${bars(count(last30, "group"))}</section>
        <section class="panel"><h2>Sektörler (30 gün)</h2>${bars(count(last30, "sector"))}</section>
      </div>
      <section class="panel" style="margin-top:20px"><h2>Son duyurulan mağdurlar</h2>
        ${scope.length ? `<div class="table-wrap"><table><thead><tr><th>Tarih</th><th>Kuruluş</th><th>Grup</th><th>Sektör</th><th>Ülke</th></tr></thead><tbody>
          ${scope.slice(0, 100).map((r) => `<tr><td style="white-space:nowrap">${fmtDate(r.date)}</td><td>${esc(r.victim)}</td><td>${link(`https://www.ransomware.live/group/${encodeURIComponent(norm(r.group).replace(/\s+/g, ""))}`, r.group)}</td><td>${esc(r.sector)}</td><td>${esc(r.country)}</td></tr>`).join("")}
        </tbody></table></div>` : `<div class="empty"><strong>Kayıt yok</strong>Bu kapsamda duyurulmuş mağdur bulunmuyor ya da kaynak henüz okunamadı.</div>`}
        <p class="small muted" style="margin-top:10px">Mağdur listeleri suç gruplarının kendi beyanlarına dayanır ve doğrulanmamıştır. Bir kuruluşun burada görünmesi, verisinin gerçekten sızdırıldığı anlamına gelmeyebilir.</p>
      </section>`;
    $$("[data-scope]").forEach((b) => b.addEventListener("click", () => { v.scope = b.dataset.scope; VIEWS.fidye(); }));
  };

  // ---------- Temel hijyen
  const CHECKLIST = [
    ["Erişim", [
      ["mfa-mail", "E-posta ve bulut hesaplarında çok faktörlü doğrulama", "Microsoft 365 / Google Workspace için tüm kullanıcılarda MFA açık; SMS yerine uygulama tercih edilir."],
      ["mfa-vpn", "VPN ve uzak erişimde çok faktörlü doğrulama", "SSL-VPN, RDP ağ geçidi ve uzak destek araçları MFA olmadan kullanılmıyor."],
      ["rdp", "İnternete açık RDP/SMB yok", "3389 ve 445 portları dışarıya kapalı; uzak erişim yalnızca VPN üzerinden."],
      ["admin", "Yönetici hesapları ayrı", "Günlük işler standart kullanıcıyla yapılıyor; yönetici hesapları e-posta okumak için kullanılmıyor."],
      ["mgmt", "Güvenlik duvarı yönetim arayüzü internete kapalı", "FortiGate/MikroTik vb. yönetim portları (HTTPS, Winbox, SSH) yalnızca iç ağdan ya da belirli IP'lerden erişilebilir."],
    ]],
    ["Yama ve envanter", [
      ["inv", "Donanım ve yazılım envanteri güncel", "Bu portaldaki Varlıklarım listesi de dahil; en az üç ayda bir gözden geçiriliyor."],
      ["edge", "Kenar cihazları 72 saat içinde yamalanıyor", "Güvenlik duvarı, VPN, e-posta sunucusu gibi internete açık sistemlerde KEV'e giren zafiyetler hızla kapatılıyor."],
      ["auto", "İşletim sistemi ve tarayıcı güncellemeleri otomatik", "Windows Update / WSUS / Intune ile istemciler en geç bir ay içinde güncelleniyor."],
      ["eol", "Desteği bitmiş sistem yok veya yalıtılmış", "Windows 7/Server 2012 gibi sistemler ağdan ayrılmış ya da kaldırılmış."],
    ]],
    ["Yedekleme ve kurtarma", [
      ["backup", "3-2-1 yedekleme ve çevrimdışı kopya", "En az bir kopya değiştirilemez (immutable) ya da ağdan fiziksel olarak ayrı."],
      ["restore", "Geri yükleme testi yapılıyor", "Son üç ay içinde kritik bir sunucu yedekten başarıyla geri yüklendi."],
      ["irp", "Olay müdahale planı ve iletişim listesi hazır", "Kim kimi arar, hangi sistemler önce kapatılır, siber sigorta ve danışman iletişim bilgileri yazılı."],
    ]],
    ["Tespit ve koruma", [
      ["edr", "Uç noktalarda EDR / yeni nesil antivirüs", "Tüm istemci ve sunucularda kurulu, merkezi konsoldan izleniyor."],
      ["mailsec", "E-posta için SPF, DKIM ve DMARC", "Alan adınız sahte gönderimlere karşı korunuyor; DMARC en az 'quarantine'."],
      ["blocklist", "Tehdit listeleri güvenlik duvarında uygulanıyor", "Bu portalın IP/alan adı listeleri veya USOM listesi güvenlik duvarında aktif."],
      ["seg", "Misafir, IoT ve kamera ağları ayrı", "Kameralar, yazıcılar ve misafir Wi-Fi kurumsal ağa erişemiyor; varsayılan parolalar değiştirildi."],
      ["logs", "Kayıtlar merkezi olarak saklanıyor", "Güvenlik duvarı ve sunucu kayıtları en az bir yıl tutuluyor; misafirlere internet sunuluyorsa 5651 sayılı Kanun kapsamındaki yükümlülükler karşılanıyor."],
    ]],
    ["İnsan ve uyum", [
      ["aware", "Oltalama farkındalık eğitimi", "Çalışanlar yılda en az bir kez eğitim ve oltalama simülasyonundan geçiyor."],
      ["kvkk", "Kişisel veri ihlali bildirim süreci", "KVKK kapsamında ihlalin öğrenilmesinden itibaren 72 saat içinde Kurul'a bildirim yapılabilecek süreç tanımlı."],
      ["vendor", "Tedarikçi ve uzak destek erişimleri kontrol altında", "Dış firmaların uzak erişimleri kayıt altında, süreli ve MFA'lı."],
    ]],
  ];
  VIEWS.hijyen = () => {
    const all = CHECKLIST.flatMap(([, items]) => items);
    const done = all.filter(([id]) => S.checks[id]).length;
    main().innerHTML = `
      <div class="page-head"><div><h1>Temel güvenlik hijyeni</h1>
        <p>Fidye yazılımı vakalarının büyük çoğunluğunu önleyen temel kontroller. İşaretler bu tarayıcıda saklanır.</p></div>
        <button class="btn subtle" id="ck-reset" type="button">İşaretleri sıfırla</button></div>
      <section class="panel"><strong>${done} / ${all.length} kontrol tamam</strong>
        <div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="${all.length}" aria-valuenow="${done}"><i style="width:${(done / all.length) * 100}%"></i></div>
        ${CHECKLIST.map(([g, items]) => `<div class="check-group"><h2>${esc(g)}</h2>${items.map(([id, t, d]) => `
          <label class="check-item ${S.checks[id] ? "done" : ""}"><input type="checkbox" data-ck="${id}" ${S.checks[id] ? "checked" : ""}><div><b>${esc(t)}</b><span>${esc(d)}</span></div></label>`).join("")}</div>`).join("")}
      </section>`;
    $$("[data-ck]").forEach((c) => c.addEventListener("change", () => { S.checks[c.dataset.ck] = c.checked; store.set("checks", S.checks); const y = scrollY; VIEWS.hijyen(); scrollTo(0, y); }));
    $("#ck-reset").addEventListener("click", () => { if (confirm("Tüm işaretler kaldırılsın mı?")) { S.checks = {}; store.set("checks", S.checks); VIEWS.hijyen(); } });
  };

  // ---------- Haftalık bülten
  VIEWS.bulten = () => {
    const lv = threatLevel();
    const wk = S.kev.filter((k) => daysSince(k.added) <= 7).sort((a, b) => b._score - a._score);
    const mine = S.kev.filter((k) => k._mine && daysSince(k.added) <= 30).sort((a, b) => b._score - a._score);
    const news = S.news.filter((n) => daysSince(n.date) <= 7).slice(0, 8);
    const cc = S.meta?.ransomware_country || "TR";
    const rw7 = S.rw.filter((r) => r.country === cc && daysSince(r.date) <= 7);
    const all = CHECKLIST.flatMap(([, i]) => i), done = all.filter(([id]) => S.checks[id]).length;
    const open = all.filter(([id]) => !S.checks[id]).slice(0, 3);
    const end = new Date(), start = new Date(Date.now() - 6 * DAY);
    const org = S.org || S.meta?.site?.organization || "";
    const actions = [];
    mine.slice(0, 3).forEach((k) => actions.push(`${k.vendor} ${k.product} için ${k.cve} yamasını uygulayın${k.ransomware ? " (fidye yazılımı gruplarınca kullanılıyor)" : ""}.`));
    if (!S.assets.length) actions.push("Portalda envanter tanımlayın; bülten şu an genel tehdit tablosunu gösteriyor.");
    open.forEach(([, t]) => actions.push(`Hijyen kontrolü: ${t}.`));
    if (!actions.length) actions.push("Rutin yama ve yedek kontrollerine devam edin.");

    main().innerHTML = `
      <div class="toolbar no-print">
        <input type="text" id="b-org" placeholder="Kuruluş adı (bültende görünür)" value="${esc(org)}" aria-label="Kuruluş adı">
        <button class="btn" type="button" onclick="window.print()">Yazdır / PDF olarak kaydet</button>
        <button class="btn subtle" type="button" id="b-copy">Metin olarak kopyala</button>
      </div>
      <article class="bulletin" id="bulletin">
        <header><h1>Haftalık siber tehdit bülteni</h1>
          <div class="muted">${esc(org) ? esc(org) + " · " : ""}${start.toLocaleDateString("tr-TR")} – ${end.toLocaleDateString("tr-TR")}</div></header>
        <section><h2>Durum: ${LEVEL_NAME[lv.level]} uyarı</h2><p>${esc(lv.text)}</p></section>
        <section><h2>Bu hafta yapılması gerekenler</h2><ol>${actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ol></section>
        <section><h2>Envanteri etkileyen zafiyetler (30 gün)</h2>
          ${mine.length ? kevMini(mine.slice(0, 10)) : `<p class="muted">${S.assets.length ? "Envanterinizi etkileyen yeni kayıt yok." : "Envanter tanımlanmadı."}</p>`}</section>
        <section><h2>Bu hafta aktif istismar listesine girenler (${wk.length})</h2>${wk.length ? kevMini(wk.slice(0, 12)) : `<p class="muted">Bu hafta yeni kayıt yok.</p>`}</section>
        <section><h2>Öne çıkan haberler</h2>${news.length ? `<ul>${news.map((n) => `<li>${link(n.link, n.title)} <span class="muted small">— ${esc(n.source)}</span></li>`).join("")}</ul>` : `<p class="muted">Haber yok.</p>`}</section>
        <section><h2>Fidye yazılımı</h2><p>Son 7 günde ${esc(cc)} kaynaklı ${rw7.length} kuruluş sızıntı sitelerinde duyuruldu${rw7.length ? `; gruplar: ${esc([...new Set(rw7.map((r) => r.group))].join(", "))}` : ""}.</p></section>
        <section><h2>Temel hijyen</h2><p>${done} / ${all.length} kontrol tamamlandı.</p></section>
        <p class="small muted" style="margin-top:28px">Kaynaklar: CISA KEV, FIRST EPSS, abuse.ch, USOM, ransomware.live. Veri tarihi: ${fmtDateTime(S.meta?.generated)}.</p>
      </article>`;
    $("#b-org").addEventListener("change", (e) => { S.org = e.target.value.trim(); store.set("org", S.org); VIEWS.bulten(); });
    $("#b-copy").addEventListener("click", () => copy($("#bulletin").innerText));
  };
  const kevMini = (arr) => `<table><thead><tr><th>Öncelik</th><th>CVE</th><th>Ürün</th><th>Eklenme</th></tr></thead><tbody>
    ${arr.map((k) => `<tr><td>${prioTag(k._prio)}</td><td class="cve">${esc(k.cve)}</td><td>${esc(k.vendor)} ${esc(k.product)}${k.ransomware ? ` <span class="tag rw">Fidye</span>` : ""}</td><td style="white-space:nowrap">${fmtDate(k.added)}</td></tr>`).join("")}</tbody></table>`;

  // ---------- Kaynaklar
  VIEWS.kaynaklar = () => {
    const src = S.meta?.sources || [];
    main().innerHTML = `
      <div class="page-head"><div><h1>Kaynaklar ve veri durumu</h1>
        <p>Veriler GitHub Actions ile her 4 saatte bir toplanır. Son çalışma: ${fmtDateTime(S.meta?.generated)} (${relTime(S.meta?.generated)}).</p></div></div>
      <div class="table-wrap"><table><thead><tr><th>Kaynak</th><th class="num">Kayıt</th><th>Not</th></tr></thead><tbody>
        ${src.map((s) => `<tr><td><span class="dot ${s.ok ? "ok" : "fail"}"></span>${s.url ? link(s.url, s.name) : esc(s.name)}</td><td class="num">${fmtNum(s.count)}</td><td class="small ${s.ok ? "muted" : ""}">${esc(s.ok ? s.note : "Hata: " + s.note)}</td></tr>`).join("")}
      </tbody></table></div>
      <section class="panel" style="margin-top:20px"><h2>Puanlama nasıl yapılıyor?</h2>
        <p>Her zafiyet için 0–105 arası bir puan hesaplanır: envanterinizle eşleşme 50, bilinen fidye yazılımı kullanımı 20, EPSS olasılığı en fazla 25, son ${newDays()} günde eklenmiş olması 10 puan. 70 ve üzeri <strong>Kritik</strong>, 45–69 <strong>Yüksek</strong>, 20–44 <strong>Orta</strong>, altı <strong>Düşük</strong> olarak gösterilir.</p>
        <p>Uyarı seviyesi: Envanterinizde son 30 günde fidye yazılımıyla ilişkili ya da EPSS ≥ %50 olan bir kayıt varsa <strong>Kırmızı</strong>; envanterinizde başka bir yeni kayıt varsa <strong>Turuncu</strong>; envanterinizi etkilemeyen ama fidye yazılımıyla ilişkili yeni kayıtlar varsa <strong>Sarı</strong>; aksi hâlde <strong>Yeşil</strong>.</p>
        <h2 style="margin-top:18px">Kullanım koşulları</h2>
        <p class="small">CISA KEV ve FIRST EPSS kamuya açıktır. abuse.ch verileri CC0 lisanslıdır. USOM listeleri Ulusal Siber Olaylara Müdahale Merkezi tarafından yayımlanır. ransomware.live verileri sitenin kullanım koşullarına tabidir. Bu portal veri doğruluğu konusunda garanti vermez.</p>
      </section>`;
  };

  // ------------------------------------------------------------------ yönlendirme
  function route() {
    const [name, qs] = (location.hash.slice(1) || "genel").split("?");
    const view = VIEWS[name] ? name : "genel";
    $$("#tabs a").forEach((a) => a.setAttribute("aria-current", a.getAttribute("href") === "#" + view ? "page" : "false"));
    $(`#tabs a[href="#${view}"]`)?.scrollIntoView({ block: "nearest", inline: "nearest" });
    try { VIEWS[view](new URLSearchParams(qs || "")); }
    catch (e) { console.error(e); main().innerHTML = `<div class="empty"><strong>Bu bölüm gösterilemedi</strong>${esc(e.message)}</div>`; }
    if (route._init) { main().focus({ preventScroll: true }); scrollTo(0, 0); }
    route._init = true;
  }

  // ------------------------------------------------------------------ tema
  function initTheme() {
    const t = store.get("theme", null);
    if (t) document.documentElement.dataset.theme = t;
    $("#theme-toggle").addEventListener("click", () => {
      const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      const next = cur === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next; store.set("theme", next);
    });
  }

  // ------------------------------------------------------------------ açılış
  async function load() {
    const get = async (n, def) => {
      try { const r = await fetch(`data/${n}?t=${Math.floor(Date.now() / 6e5)}`); if (!r.ok) throw new Error(r.status); return await r.json(); }
      catch (e) { console.warn("Yüklenemedi:", n, e); return def; }
    };
    const [meta, kev, iocs, news, rw] = await Promise.all([
      get("meta.json", null), get("kev.json", { items: [], epss: {} }), get("iocs.json", { items: [] }),
      get("news.json", { items: [] }), get("ransomware.json", { items: [] }),
    ]);
    if (!meta) {
      main().innerHTML = `<div class="panel empty"><strong>Veri dosyaları bulunamadı</strong>
        Depoda <code>data/</code> klasörü henüz oluşmamış. GitHub'da Actions sekmesinden “CTI verisini güncelle ve yayınla” iş akışını çalıştırın ya da yerelde <code>python scripts/fetch_feeds.py --demo</code> komutunu kullanın.</div>`;
      $("#updated").textContent = "Veri yok";
      return;
    }
    Object.assign(S, { meta, kev: kev.items || [], epss: kev.epss || {}, iocs: iocs.items || [], news: news.items || [], rw: rw.items || [] });
    if (meta.site?.title) { $("#site-title").textContent = meta.site.title; document.title = meta.site.title; }
    $("#site-org").textContent = S.org || meta.site?.organization || "";
    $("#updated").innerHTML = `Güncellendi: <time datetime="${esc(meta.generated)}" title="${esc(fmtDateTime(meta.generated))}">${esc(relTime(meta.generated))}</time>`;
    $("#demo-banner").hidden = !meta.demo;
    enrichKev(); buildIndex(); route();
  }

  initTheme();
  addEventListener("hashchange", route);
  load();
})();
