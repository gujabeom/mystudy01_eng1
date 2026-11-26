/* 영어 문법 노트 — 단원 목록 · 단원 내용 · 사이트 설정을 읽어 보여준다.
 * 게시된 사이트: data/content.enc (비밀번호로 암호화한 묶음, scripts/publish_web.py 가 만든다)
 *   암호화 형식은 naver_land 와 같다: PBKDF2-SHA256 → AES-256-GCM (+gzip).
 *   '이 기기에서 기억'은 비밀번호가 아니라 도출된 키를 저장한다.
 * 로컬 미리보기(web/ 폴더): content.enc 가 없으면 data/*.json 평문을 그대로 읽는다.
 * 화면은 해시 주소로 나뉜다:
 *   #/                 홈 (카테고리 목록 · 진도)
 *   #/c/<id>/<tab>     카테고리 (tab: basics · advanced · quiz · confusions · log)
 *   #/review           오답노트 (이 기기 브라우저에만 저장)
 *   #/ask?cat=&ref=    질문·오답 올리기 (사이트 설정 feedback 채널로 연결)
 * 본문 문자열의 간단한 표기: **굵게**  __밑줄__  ==형광==  ~~취소~~  줄바꿈(\n)
 */
(() => {
  "use strict";
  const PROGRESS_STORE = "eng.progress.v1";   // { 문제id: { cat, last: "ok"|"no", tries, wrong } }
  const TABS = [
    { id: "basics", label: "기초" },
    { id: "advanced", label: "심화" },
    { id: "notes", label: "핵심노트" },
    { id: "quiz", label: "문제" },
    { id: "confusions", label: "헷갈리는 것" },
    { id: "log", label: "업데이트" },
  ];
  const CIRCLED = ["①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧"];
  const $ = (s, el = document) => el.querySelector(s);
  const view = $("#view");
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* 저장 불가 환경 */ } },
    del(k) { try { localStorage.removeItem(k); } catch { /* */ } },
  };
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  // 간단 표기 → HTML (항상 escape 먼저)
  const fmt = (s) => esc(s)
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/__(.+?)__/g, "<u>$1</u>")
    .replace(/==(.+?)==/g, "<mark>$1</mark>")
    .replace(/~~(.+?)~~/g, "<s>$1</s>")
    .replace(/\n/g, "<br>");
  const paras = (body) => (Array.isArray(body) ? body : body ? [body] : [])
    .map((p) => `<p>${fmt(p)}</p>`).join("");

  // ---------- 데이터 ----------
  let index = null;
  let bundle = null;            // 복호화한 묶음 { index, cats, config } (게시된 사이트)
  const catCache = new Map();
  async function getJSON(url) {
    const r = await fetch(url, { cache: "no-cache" });
    if (!r.ok) throw new Error(`${url} ${r.status}`);
    return r.json();
  }
  async function loadIndex() {
    if (!index) index = bundle ? bundle.index : await getJSON("data/index.json");
    return index;
  }
  async function loadCat(id) {
    if (bundle) {
      if (!bundle.cats[id]) throw new Error(`단원 없음: ${id}`);
      return bundle.cats[id];
    }
    if (!catCache.has(id)) catCache.set(id, await getJSON(`data/categories/${encodeURIComponent(id)}.json`));
    return catCache.get(id);
  }

  // ---------- 잠금 (암호화된 내용) ----------
  const KEY_STORE = "eng.key.v1";
  const b64 = (t) => Uint8Array.from(atob(t), (c) => c.charCodeAt(0));
  const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  let enc = null;
  async function deriveKey(password, salt, iter) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
      base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
  }
  async function decryptWith(key) {
    let plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(enc.iv) }, key, b64(enc.ct));
    if (enc.z === "gzip") {
      const ds = new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip"));
      plain = await new Response(ds).arrayBuffer();
    }
    return JSON.parse(new TextDecoder().decode(plain));
  }
  async function tryStoredKey() {
    const raw = store.get(KEY_STORE);
    if (!raw) return false;
    try {
      const s = JSON.parse(raw);
      if (s.salt !== enc.salt || s.iter !== enc.iter) return false;   // 비밀번호가 바뀜
      const key = await crypto.subtle.importKey("raw", b64(s.key), "AES-GCM", false, ["decrypt"]);
      bundle = await decryptWith(key);
      return true;
    } catch { store.del(KEY_STORE); return false; }
  }
  function showLock(msg) {
    $("#app").hidden = true;
    $("#lock").hidden = false;
    $("#lockMsg").textContent = msg || "";
    $("#pw").focus();
  }
  async function unlock(e) {
    e.preventDefault();
    const btn = $("#unlockBtn");
    btn.disabled = true; btn.textContent = "여는 중…";
    try {
      const key = await deriveKey($("#pw").value, b64(enc.salt), enc.iter);
      bundle = await decryptWith(key);
      if ($("#remember").checked) {
        const raw = await crypto.subtle.exportKey("raw", key);
        store.set(KEY_STORE, JSON.stringify({ salt: enc.salt, iter: enc.iter, key: b64e(raw) }));
      }
      $("#pw").value = "";
      start();
    } catch {
      showLock("비밀번호가 맞지 않습니다.");
    } finally {
      btn.disabled = false; btn.textContent = "열기";
    }
  }
  function lockNow() {
    store.del(KEY_STORE);
    bundle = null; index = null;
    showLock("");
  }

  // ---------- 진도 ----------
  const progress = (() => {
    let p = {};
    try { p = JSON.parse(store.get(PROGRESS_STORE) || "{}") || {}; } catch { p = {}; }
    const save = () => { store.set(PROGRESS_STORE, JSON.stringify(p)); badge(); };
    return {
      get: (qid) => p[qid],
      record(cat, qid, ok) {
        const e = p[qid] || { cat, tries: 0, wrong: 0 };
        e.cat = cat; e.tries += 1; if (!ok) e.wrong += 1; e.last = ok ? "ok" : "no";
        p[qid] = e; save();
      },
      clear(qid) { delete p[qid]; save(); },
      doneIn: (cat) => Object.values(p).filter((e) => e.cat === cat).length,
      wrongIds: () => Object.keys(p).filter((k) => p[k].last === "no"),
    };
  })();
  // ---------- 한 번 탭 피드백 (사이트 설정 rating 설문지로 화면 뒤에서 제출) ----------
  const RATED_STORE = "eng.rated.v1";   // { 카드·문제id: { level: "쉬움", 예제 더: true, … } }
  const DEVICE_STORE = "eng.device";    // 이 브라우저의 무작위 번호 (같은 사람의 반복 응답 구분용)
  const LEVELS = [["쉬움", "쉬워요"], ["적당", "적당해요"], ["어려움", "어려워요"]];
  const REQUESTS = [["예제 더", "예제 더 ＋"], ["설명 더", "설명 더 ＋"]];
  let currentCat = "";
  const rating = (() => {
    let r = {};
    try { r = JSON.parse(store.get(RATED_STORE) || "{}") || {}; } catch { r = {}; }
    let dev = store.get(DEVICE_STORE);
    if (!dev) { dev = Math.random().toString(36).slice(2, 10); store.set(DEVICE_STORE, dev); }
    return {
      get: (id) => r[id] || {},
      mark(id, key, val) { r[id] = { ...(r[id] || {}), [key]: val }; store.set(RATED_STORE, JSON.stringify(r)); },
      send(cat, item, kind, value) {
        const c = (window.SITE_CONFIG || {}).rating;
        if (!c?.url) return;
        const f = c.fields;
        const body = new URLSearchParams();
        body.set(f.cat, cat); body.set(f.item, item); body.set(f.kind, kind); body.set(f.value, value); body.set(f.device, dev);
        // 응답 내용을 읽을 수는 없지만(no-cors) 제출은 된다
        fetch(c.url, { method: "POST", mode: "no-cors", body }).catch(() => { /* 오프라인 등 */ });
      },
    };
  })();
  function rateBar(item, cat = currentCat, withRequests = true) {
    const s = rating.get(item);
    const btn = (k, v, label, on) =>
      `<button type="button" data-k="${k}" data-v="${esc(v)}" class="${on ? "on" : ""}" ${k === "req" && on ? "disabled" : ""}>${label}</button>`;
    return `<div class="rate" data-cat="${esc(cat)}" data-item="${esc(item)}">
      <span class="lbl">${withRequests ? "이 설명은" : "이 문제는"}</span>
      ${LEVELS.map(([v, l]) => btn("level", v, l, s.level === v)).join("")}
      ${withRequests ? REQUESTS.map(([v, l]) => btn("req", v, l, s[v])).join("") : ""}
      <span class="sent" ${Object.keys(s).length ? "" : "hidden"}>✓ 전달됨</span>
    </div>`;
  }
  document.addEventListener("click", (e) => {
    const b = e.target.closest(".rate button");
    if (!b || b.disabled) return;
    const bar = b.closest(".rate");
    const { cat, item } = bar.dataset;
    const { k, v } = b.dataset;
    if (k === "level") {
      if (rating.get(item).level === v) return;
      rating.mark(item, "level", v);
      rating.send(cat, item, "평가", v);
      bar.querySelectorAll('[data-k="level"]').forEach((x) => x.classList.toggle("on", x === b));
    } else {
      rating.mark(item, v, true);
      rating.send(cat, item, "요청", v);
      b.classList.add("on"); b.disabled = true;
    }
    bar.querySelector(".sent").hidden = false;
  });

  function badge() {
    const n = progress.wrongIds().length;
    const b = $("#wrongCount");
    b.textContent = n; b.hidden = n === 0;
  }

  // ---------- 질문하기 링크 ----------
  function feedbackUrl(catId, ref) {
    const f = (window.SITE_CONFIG || {}).feedback || {};
    if (!f.url) return "";
    const cat = index?.categories.find((c) => c.id === catId);
    const catLabel = cat ? cat.title : (catId || "");
    if (f.type === "github-issue") {
      const q = new URLSearchParams({ template: f.template || "", title: `[${catLabel}] ${ref || "질문"}` });
      if (catLabel) q.set("category", catLabel);
      if (ref) q.set("ref", ref);
      return `${f.url}?${q}`;
    }
    const q = new URLSearchParams({ usp: "pp_url" });
    if (f.prefill?.category && catLabel) q.set(f.prefill.category, catLabel);
    if (f.prefill?.ref && ref) q.set(f.prefill.ref, ref);
    return `${f.url}?${q}`;
  }
  const askHref = (cat, ref) => `#/ask?${new URLSearchParams({ ...(cat && { cat }), ...(ref && { ref }) })}`;

  // ---------- 화면: 홈 ----------
  function renderHome(idx) {
    const groups = [];
    for (const c of idx.categories) {
      let g = groups.find((x) => x.name === c.group);
      if (!g) groups.push((g = { name: c.group, items: [] }));
      g.items.push(c);
    }
    const ready = idx.categories.filter((c) => c.status === "ready").length;
    view.innerHTML = `
      <section class="hero">
        <h2 style="margin:0">고등 영어 문법 · 내신 / 수능</h2>
        <p class="muted small">카테고리 ${idx.categories.length}개 중 ${ready}개 준비됨 · ★ 는 수능 어법 출제 빈도</p>
      </section>
      ${groups.map((g) => `
        <div class="group-title">${esc(g.name)}</div>
        <div class="cat-list">${g.items.map(catRow).join("")}</div>`).join("")}`;
  }
  function catRow(c) {
    const total = c.counts?.quiz || 0;
    const done = progress.doneIn(c.id);
    const pct = total ? Math.min(100, Math.round((done / total) * 100)) : 0;
    const inner = `
      <div class="cat-head">
        <span class="cat-title">${esc(c.no)}. ${esc(c.title)}</span>
        <span class="stars" title="수능 어법 빈도">${"★".repeat(c.freq || 0)}</span>
      </div>
      <div class="cat-sub">${esc(c.subtitle || "")}</div>
      ${c.status === "ready"
        ? `<div class="bar" aria-label="푼 문제 ${done}/${total}"><span style="width:${pct}%"></span></div>
           <div class="cat-sub">문제 ${done}/${total}</div>`
        : `<div class="cat-sub"><span class="pill gray">준비 중</span></div>`}`;
    return c.status === "ready"
      ? `<a class="cat" href="#/c/${esc(c.id)}/basics">${inner}</a>`
      : `<div class="cat planned">${inner}</div>`;
  }

  // ---------- 화면: 카테고리 ----------
  function renderCat(cat, tab) {
    currentCat = cat.id;
    const counts = {
      basics: cat.basics?.length, advanced: cat.advanced?.length, quiz: cat.quiz?.length,
      confusions: cat.confusions?.length, log: cat.changelog?.length, notes: cat.notes?.length,
    };
    view.innerHTML = `
      <a class="crumb" href="#/">← 전체 카테고리</a>
      <div class="cat-top">
        <h2>${esc(cat.title)}</h2>
        <div class="muted small">${esc(cat.subtitle || "")}</div>
      </div>
      <nav class="tabs" role="tablist">
        ${TABS.map((t) => `<button role="tab" data-tab="${t.id}" aria-selected="${t.id === tab}">${t.label}${
          t.id === "quiz" && counts.quiz ? ` <span class="muted small">${counts.quiz}</span>` : ""}</button>`).join("")}
      </nav>
      <div id="tabBody"></div>`;
    view.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
      location.replace(`#/c/${cat.id}/${b.dataset.tab}`);
    }));
    const body = $("#tabBody");
    if (tab === "basics" || tab === "advanced") body.innerHTML = (cat[tab] || []).map(section).join("") || empty();
    else if (tab === "notes") body.innerHTML = notesIntro(cat) + ((cat.notes || []).map(noteCard).join("") || empty());
    else if (tab === "confusions") body.innerHTML = (cat.confusions || []).map(confusion).join("") || empty();
    else if (tab === "log") body.innerHTML = changelog(cat);
    else renderQuizList(body, cat, cat.quiz || []);
  }
  const empty = () => `<p class="empty">아직 내용이 없습니다.</p>`;

  // ---------- 핵심노트: 문제를 보자마자 '무엇을 묻는지' 알아채고 공식으로 푸는 정리노트 ----------
  const notesIntro = (cat) => cat.notes?.length
    ? `<p class="small muted" style="margin:12px 0 0">문제를 다 해석하지 않고도 '무엇을 묻는지' 알아채는 정리노트입니다. 30초 확인을 반복해서 손에 익히세요.</p>` : "";
  function noteCard(n, i) {
    const sec = (label, html) => (html ? `<div class="nsec"><div class="nlabel">${label}</div>${html}</div>` : "");
    return `<article class="card note">
      <div class="note-head"><span class="pill">핵심요약 ${i + 1}</span>${tierPill(n)}</div>
      <h3>${fmt(n.title)}</h3>
      ${sec("🎯 이렇게 물어본다", n.signals?.length ? `<ul class="nlist">${n.signals.map((t) => `<li>${fmt(t)}</li>`).join("")}</ul>` : "")}
      ${sec("⚡ 판단 공식", n.rules?.length ? `<ol class="nrules">${n.rules.map((t) => `<li>${fmt(t)}</li>`).join("")}</ol>` : "")}
      ${sec("📌 핵심 표현 (통째로 외우기)", n.chunks?.length ? `<div class="chunks en">${n.chunks.map((t) => `<span>${fmt(t)}</span>`).join("")}</div>` : "")}
      ${sec("⚠️ 함정", n.traps?.length ? `<ul class="traps">${n.traps.map((t) => `<li><span class="bad en">✗ ${fmt(t.bad)}</span> → <span class="good en">${fmt(t.good)}</span>${t.why ? `<span class="why">${fmt(t.why)}</span>` : ""}</li>`).join("")}</ul>` : "")}
      ${sec(`⏱ 30초 확인 <button type="button" class="linkish" data-drill-all>모두 보기</button>`, n.drill?.length ? `<ol class="drill">${n.drill.map((d) => `<li><button type="button" class="drill-q en">${fmt(d.q)}</button><span class="drill-a" hidden>${fmt(d.a)}</span></li>`).join("")}</ol>` : "")}
      ${n.id ? rateBar(n.id) : ""}
    </article>`;
  }
  document.addEventListener("click", (e) => {
    const q = e.target.closest(".drill-q");
    if (q) { const a = q.nextElementSibling; a.hidden = !a.hidden; q.classList.toggle("open", !a.hidden); return; }
    const all = e.target.closest("[data-drill-all]");
    if (all) {
      const card = all.closest(".note");
      const show = all.textContent === "모두 보기";
      card.querySelectorAll(".drill-a").forEach((a) => { a.hidden = !show; });
      card.querySelectorAll(".drill-q").forEach((x) => x.classList.toggle("open", show));
      all.textContent = show ? "모두 가리기" : "모두 보기";
    }
  });
  const sourcePill = (s) => (s === "student" ? ` <span class="pill student">학생 질문에서 추가</span>` : "");

  function section(s) {
    return `<article class="card sec">
      <h3>${esc(s.heading)}${tierPill(s)}${sourcePill(s.source)}</h3>
      <div class="body">${paras(s.body)}</div>
      ${s.table ? table(s.table) : ""}
      ${s.cases?.length ? casesList(s.cases) : ""}
      ${s.examples?.length ? examples(s.examples) : ""}
      ${s.more?.length ? moreExamples(s.more, s.cases) : ""}
      ${s.tip ? `<div class="tip">💡 ${fmt(s.tip)}</div>` : ""}
      ${s.id ? rateBar(s.id) : ""}
    </article>`;
  }
  function table(t) {
    return `<div class="tbl-wrap"><table>
      ${t.head ? `<thead><tr>${t.head.map((h) => `<th>${fmt(h)}</th>`).join("")}</tr></thead>` : ""}
      <tbody>${t.rows.map((r) => `<tr>${r.map((c) => `<td>${fmt(c)}</td>`).join("")}</tr>`).join("")}</tbody>
    </table></div>`;
  }
  // 카드가 다루는 경우 ①②③ — 예문의 case 번호와 짝을 이룬다
  const casesList = (cases) =>
    `<ol class="cases">${cases.map((c, i) => `<li><span class="cn">${CIRCLED[i]}</span><span>${fmt(c)}</span></li>`).join("")}</ol>`;
  function examples(list, showCase = true) {
    return `<ul class="ex">${list.map((e) => `<li class="${e.wrong ? "wrong" : ""}">
      <span class="en">${e.case && showCase ? `<span class="cn">${CIRCLED[e.case - 1]}</span>` : ""}${e.wrong ? "✗ " : ""}${fmt(e.en)}</span>
      ${e.ko ? `<span class="ko">${fmt(e.ko)}</span>` : ""}
      ${e.note ? `<span class="note">${fmt(e.note)}</span>` : ""}
    </li>`).join("")}</ul>`;
  }
  // 예문 더보기: 처음에는 접어 두고, 누르면 펼친다
  // cases 가 있으면 경우별로 묶고, 묶음 안에서는 맞는 예문 → 틀린 예문 순서
  function moreExamples(list, cases) {
    let inner;
    if (cases?.length) {
      const groups = cases.map((label, i) => ({ label, i, items: list.filter((e) => e.case === i + 1) }));
      const rest = list.filter((e) => !e.case || e.case > cases.length);
      inner = groups.filter((g) => g.items.length).map((g) => `
        <div class="grp"><span class="cn">${CIRCLED[g.i]}</span><span>${fmt(g.label)}</span></div>
        ${examples([...g.items.filter((e) => !e.wrong), ...g.items.filter((e) => e.wrong)], false)}`).join("")
        + (rest.length ? `<div class="grp">기타</div>${examples(rest, false)}` : "");
    } else inner = examples(list);
    return `<details class="more"><summary>예문 더보기 <span class="muted small">${list.length}</span></summary>${inner}</details>`;
  }
  function confusion(c) {
    return `<article class="card sec">
      <h3>${esc(c.title)}${tierPill(c)}${sourcePill(c.source)}</h3>
      <div class="body">${paras(c.body)}</div>
      ${c.points?.length ? `<div class="vs">${c.points.map((p) => `<div><b>${fmt(p.label)}</b>${fmt(p.body)}</div>`).join("")}</div>` : ""}
      ${c.table ? table(c.table) : ""}
      ${c.cases?.length ? casesList(c.cases) : ""}
      ${c.examples?.length ? examples(c.examples) : ""}
      ${c.more?.length ? moreExamples(c.more, c.cases) : ""}
      ${c.tip ? `<div class="tip">💡 ${fmt(c.tip)}</div>` : ""}
      ${c.id ? rateBar(c.id) : ""}
    </article>`;
  }
  function changelog(cat) {
    const list = cat.changelog || [];
    return `<div class="card">
      <p class="small muted">학생 질문·오답을 바탕으로 내용이 추가되면 여기에 기록됩니다.</p>
      ${list.length ? `<ul class="log">${list.map((l) => `<li><b>${esc(l.date)}</b> ${fmt(l.note)}${sourcePill(l.source)}</li>`).join("")}</ul>` : empty()}
      <p style="margin-top:14px"><a class="btn ghost small" href="${askHref(cat.id)}">이 단원에 대해 질문하기</a></p>
    </div>`;
  }

  // ---------- 문제 ----------
  function renderQuizList(el, cat, items, opts = {}) {
    let filter = "all";
    const draw = () => {
      const shown = items.filter((q) => {
        const p = progress.get(q.id);
        return filter === "all" || (filter === "todo" && !p) || (filter === "wrong" && p?.last === "no");
      });
      el.innerHTML = `
        ${opts.fixed ? "" : `<div class="quiz-bar">
          <div class="chips" role="group" aria-label="보기">
            ${[["all", "전체"], ["todo", "안 푼 문제"], ["wrong", "틀린 문제"]].map(([k, l]) =>
              `<button class="btn small ${filter === k ? "" : "ghost"}" data-f="${k}">${l}</button>`).join(" ")}
          </div>
        </div>`}
        <div class="qs">${shown.length ? "" : empty()}</div>`;
      el.querySelectorAll("[data-f]").forEach((b) => b.addEventListener("click", () => { filter = b.dataset.f; draw(); }));
      const qs = $(".qs", el);
      shown.forEach((q, i) => qs.appendChild(quizCard(opts.catOf ? opts.catOf(q) : cat, q, i + 1)));
    };
    draw();
  }

  const tierPill = (x) => (x.tier === "fl" ? ` <span class="pill fl">외고·상위권</span>` : "");
  function qMeta(q, n) {
    const prev = progress.get(q.id);
    return `<div class="q-meta">
        <span class="pill">${n}</span>
        <span class="pill gray">${"●".repeat(q.level || 1)}${"○".repeat(3 - (q.level || 1))}</span>
        ${q.exam ? `<span class="pill gray">${esc(q.exam)}</span>` : ""}${tierPill(q)}
        ${prev ? `<span class="pill ${prev.last === "ok" ? "" : "student"}">${prev.last === "ok" ? "맞힘" : "틀림"}</span>` : ""}
        ${q.source === "student" ? `<span class="pill student">학생 질문</span>` : ""}
      </div>`;
  }
  // 서술형: 인정 답안과 같으면 자동 정답, 다르면 모범답안을 보고 스스로 채점
  const norm = (t) => String(t).toLowerCase().replace(/[‘’]/g, "'").replace(/[“”]/g, '"')
    .replace(/\*\*/g, "").replace(/\s+/g, " ").replace(/\s+([,.?!])/g, "$1").replace(/[.!]$/, "").trim();
  function writeCard(cat, q, n) {
    const card = document.createElement("article");
    card.className = "card";
    card.innerHTML = `${qMeta(q, n)}
      <div class="q-text">${fmt(q.q)}</div>
      ${q.passage ? `<div class="passage en">${fmt(q.passage)}</div>` : ""}
      <textarea class="w-input en" rows="2" placeholder="답을 영어로 쓰세요" autocapitalize="off" autocomplete="off" spellcheck="false"></textarea>
      <div class="q-actions"><button type="button" class="btn small" data-act="grade">채점</button></div>
      <div class="result"></div>`;
    const input = $(".w-input", card);
    const finish = (cat, ok, how, typed) => {
      progress.record(cat.id, q.id, ok);
      rating.send(cat.id, q.id, "풀이", `서술 ${ok ? "정답" : "오답"}(${how}): ${typed.slice(0, 200)}`);
    };
    $("[data-act=grade]", card).addEventListener("click", () => {
      const typed = input.value.trim();
      if (!typed) { input.focus(); return; }
      input.readOnly = true;
      $("[data-act=grade]", card).disabled = true;
      const auto = (q.answers || []).some((a) => norm(a) === norm(typed));
      const res = $(".result", card);
      res.innerHTML = `
        <div class="explain">
          <div class="verdict ${auto ? "ok" : ""}">${auto ? "정답!" : "모범답안과 비교해 보세요"}</div>
          <p><b>모범답안</b><br><span class="en">${fmt(q.model)}</span></p>
          ${q.points?.length ? `<p><b>채점 포인트</b></p><ul class="pts">${q.points.map((t) => `<li>${fmt(t)}</li>`).join("")}</ul>` : ""}
          ${paras(q.explain)}
          ${auto ? "" : `<div class="self"><span class="small muted">내 답이 맞았나요?</span>
            <button type="button" class="btn small" data-self="1">맞게 썼어요</button>
            <button type="button" class="btn ghost small" data-self="0">틀렸어요</button></div>`}
        </div>
        <div class="q-actions">
          <button type="button" class="btn ghost small" data-act="retry">다시 풀기</button>
          <a class="btn ghost small" href="${askHref(cat.id, q.id)}">이 문제 질문하기</a>
        </div>
        ${rateBar(q.id, cat.id, false)}`;
      if (auto) finish(cat, true, "자동", typed);
      res.querySelectorAll("[data-self]").forEach((b) => b.addEventListener("click", () => {
        const ok = b.dataset.self === "1";
        finish(cat, ok, "자가", typed);
        b.closest(".self").innerHTML = `<span class="verdict ${ok ? "ok" : "no"}">${ok ? "맞힘으로 기록했어요" : "오답노트에 넣었어요"}</span>`;
      }));
      $("[data-act=retry]", card).addEventListener("click", () => card.replaceWith(quizCard(cat, q, n)));
    });
    return card;
  }

  function quizCard(cat, q, n) {
    if (q.type === "write") return writeCard(cat, q, n);
    const card = document.createElement("article");
    card.className = "card";
    let choices = q.choices || [];
    let passage = "";
    if (q.type === "grammar5") {
      choices = [];
      passage = esc(q.passage).replace(/\{(\d):(.+?)\}/g, (_, d, t) => {
        choices[Number(d) - 1] = t;
        return `${CIRCLED[Number(d) - 1]}<u>${t}</u>`;
      }).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/\n/g, "<br>");
      choices = choices.map((t, i) => `${CIRCLED[i]} ${t}`);
    } else if (q.passage) passage = fmt(q.passage);
    const isOX = q.type === "ox";
    const opts = isOX ? ["O", "X"] : choices;
    card.innerHTML = `
      ${qMeta(q, n)}
      <div class="q-text">${fmt(q.q)}</div>
      ${passage ? `<div class="passage en">${passage}</div>` : ""}
      <div class="choices ${isOX ? "ox" : ""}">
        ${opts.map((c, i) => `<button type="button" data-i="${i}">${isOX ? c : `${q.type === "grammar5" ? "" : `${CIRCLED[i]} `}${fmt(c)}`}</button>`).join("")}
      </div>
      <div class="result"></div>`;
    const answerIdx = isOX ? (q.answer ? 0 : 1) : q.answer;
    card.querySelectorAll(".choices button").forEach((b) => b.addEventListener("click", () => {
      const i = Number(b.dataset.i);
      const ok = i === answerIdx;
      progress.record(cat.id, q.id, ok);
      rating.send(cat.id, q.id, "풀이", `${ok ? "정답" : "오답"}:${i + 1}`);
      card.querySelectorAll(".choices button").forEach((x) => {
        x.disabled = true;
        if (Number(x.dataset.i) === answerIdx) x.classList.add("correct");
      });
      if (!ok) b.classList.add("picked-wrong");
      $(".result", card).innerHTML = `
        <div class="explain">
          <div class="verdict ${ok ? "ok" : "no"}">${ok ? "정답!" : `오답 — 정답은 ${isOX ? (q.answer ? "O" : "X") : CIRCLED[answerIdx]}`}</div>
          ${paras(q.explain)}
        </div>
        <div class="q-actions">
          <button type="button" class="btn ghost small" data-act="retry">다시 풀기</button>
          <a class="btn ghost small" href="${askHref(cat.id, q.id)}">이 문제 질문하기</a>
        </div>
        ${rateBar(q.id, cat.id, false)}`;
      $("[data-act=retry]", card).addEventListener("click", () => card.replaceWith(quizCard(cat, q, n)));
    }));
    return card;
  }

  // ---------- 화면: 오답노트 ----------
  async function renderReview(idx) {
    const ids = progress.wrongIds();
    view.innerHTML = `<h2>오답노트</h2>
      <p class="muted small">마지막으로 틀린 문제가 모입니다. 다시 풀어 맞히면 빠집니다. (이 기기 브라우저에만 저장)</p>
      <div id="rv"></div>`;
    const rv = $("#rv");
    if (!ids.length) { rv.innerHTML = `<p class="empty">틀린 문제가 없습니다 👍</p>`; return; }
    const byCat = new Map();
    for (const qid of ids) {
      const c = progress.get(qid).cat;
      if (!byCat.has(c)) byCat.set(c, []);
      byCat.get(c).push(qid);
    }
    for (const [cid, qids] of byCat) {
      const meta = idx.categories.find((c) => c.id === cid);
      if (!meta || meta.status !== "ready") continue;
      const cat = await loadCat(cid);
      const items = (cat.quiz || []).filter((q) => qids.includes(q.id));
      if (!items.length) continue;
      const box = document.createElement("section");
      box.innerHTML = `<h3 style="margin-top:20px"><a href="#/c/${esc(cid)}/basics">${esc(cat.title)}</a></h3><div></div>`;
      rv.appendChild(box);
      renderQuizList(box.lastElementChild, cat, items, { fixed: true });
    }
  }

  // ---------- 화면: 질문하기 ----------
  function renderAsk(idx, params) {
    const cat = params.get("cat") || "";
    const ref = params.get("ref") || "";
    const url = feedbackUrl(cat, ref);
    const catMeta = idx.categories.find((c) => c.id === cat);
    view.innerHTML = `
      <h2>질문 · 오답 올리기</h2>
      <div class="card">
        <p>궁금한 점, 틀린 문제, 학교·학원에서 새로 본 문제를 올려 주세요. 내용을 확인해 해당 단원에 설명과 문제를 보완합니다.</p>
        <ul class="small">
          <li>문제집·시험지 사진을 찍어 올려도 됩니다.</li>
          <li>어디가 헷갈렸는지, 내가 고른 답과 이유를 한 줄 적어 주면 더 정확하게 보완할 수 있어요.</li>
          <li>보완된 내용은 각 단원의 <b>업데이트</b> 탭에 기록됩니다.</li>
        </ul>
        ${catMeta || ref ? `<p class="small muted">자동으로 채워지는 정보: ${catMeta ? `단원 <b>${esc(catMeta.title)}</b>` : ""} ${ref ? `· 문제 <b>${esc(ref)}</b>` : ""}</p>` : ""}
        ${url
          ? `<a class="btn" style="width:100%" href="${esc(url)}" target="_blank" rel="noopener">올리기 화면 열기</a>`
          : `<div class="notice">아직 올리기 채널이 연결되지 않았습니다. 관리자가 <code>data/site-config.json</code> 의 <code>feedback.url</code> 을 채우면 이 버튼이 나타납니다.</div>`}
      </div>`;
  }

  // ---------- 라우터 ----------
  async function route() {
    const raw = location.hash.replace(/^#/, "") || "/";
    const [path, qs] = raw.split("?");
    const parts = path.split("/").filter(Boolean);
    try {
      const idx = await loadIndex();
      $("#builtAt").textContent = idx.updated ? `내용 업데이트 ${idx.updated}` : "";
      if (parts[0] === "c" && parts[1]) {
        const tab = TABS.some((t) => t.id === parts[2]) ? parts[2] : "basics";
        renderCat(await loadCat(parts[1]), tab);
      } else if (parts[0] === "review") await renderReview(idx);
      else if (parts[0] === "ask") renderAsk(idx, new URLSearchParams(qs || ""));
      else renderHome(idx);
    } catch (e) {
      view.innerHTML = `<p class="notice">내용을 불러오지 못했습니다. 잠시 뒤 새로고침해 주세요.<br><span class="small">${esc(e.message)}</span></p>`;
    }
    if (!route.keepScroll) window.scrollTo(0, 0);
  }
  let started = false;
  function start() {
    window.SITE_CONFIG = bundle ? bundle.config : window.SITE_CONFIG;
    $("#lock").hidden = true;
    $("#app").hidden = false;
    $("#lockBtn").hidden = !enc;
    if (!started) { window.addEventListener("hashchange", route); started = true; }
    badge();
    route();
  }
  async function boot() {
    $("#lockForm").addEventListener("submit", unlock);
    $("#lockBtn").addEventListener("click", lockNow);
    const r = await fetch("data/content.enc", { cache: "no-cache" }).catch(() => null);
    if (r && r.ok) {
      enc = await r.json();
      if (await tryStoredKey()) start(); else showLock("");
    } else {
      // 로컬 미리보기: 평문 데이터
      window.SITE_CONFIG = await getJSON("data/site-config.json").catch(() => ({}));
      start();
    }
  }
  boot();
})();
