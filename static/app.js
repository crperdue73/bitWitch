// bitWitch front end. No framework, no build step.

const $ = (id) => document.getElementById(id);
const attackSel = $("attack");
const descEl = $("desc");
const portEl = $("port");
const outEl = $("out");
const statusEl = $("status");
const form = $("run");
const runBtn = form.querySelector("button");

let catalog = [];

async function loadCatalog() {
  const res = await fetch("/api/catalog");
  if (!res.ok) return;
  catalog = await res.json();

  let currentGroup = "";
  for (const a of catalog) {
    if (a.category !== currentGroup) {
      currentGroup = a.category;
      const group = document.createElement("optgroup");
      group.label = currentGroup;
      attackSel.appendChild(group);
    }
    const opt = document.createElement("option");
    opt.value = a.name;
    opt.textContent = a.label;
    attackSel.lastChild === undefined ? null : null;
    attackSel.querySelector(`optgroup[label="${currentGroup}"]`).appendChild(opt);
  }
  syncForm();
}

function selected() {
  return catalog.find((a) => a.name === attackSel.value);
}

function syncForm() {
  const a = selected();
  if (!a) return;
  descEl.textContent = a.desc;
  portEl.disabled = false;
  portEl.placeholder = a.needs_port ? "required" : "blank if unused";
}

attackSel.addEventListener("change", syncForm);

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  runBtn.disabled = true;
  outEl.textContent = "";
  setStatus("running", "starting");

  const body = new FormData(form);
  const res = await fetch("/api/run", { method: "POST", body });
  if (!res.ok) {
    // 403 carries the scope reason in the body. Show it as-is: a student who
    // hits the limit should read the actual rule, not "error".
    const msg = await res.text();
    let text = msg;
    try { text = JSON.parse(msg).detail || msg; } catch {}
    outEl.textContent = "refused: " + text;
    setStatus("blocked", res.status === 403 ? "out of scope" : "refused");
    runBtn.disabled = false;
    return;
  }
  const job = await res.json();
  append(job.lines);
  poll(job.id, job.cursor);
});

function append(lines) {
  if (!lines || !lines.length) return;
  outEl.textContent += (outEl.textContent ? "\n" : "") + lines.join("\n");
  outEl.scrollTop = outEl.scrollHeight;
}

function setStatus(cls, text) {
  statusEl.className = "status " + cls;
  statusEl.textContent = text;
}

async function poll(id, cursor) {
  const res = await fetch(`/api/job/${id}?since=${cursor}`);
  if (!res.ok) {
    setStatus("fail", "lost job");
    runBtn.disabled = false;
    return;
  }
  const job = await res.json();
  append(job.lines);

  if (job.status === "running") {
    setStatus("running", `running ${job.elapsed}s`);
    setTimeout(() => poll(id, job.cursor), 600);
  } else {
    setStatus(job.status, `${job.status} ${job.elapsed}s`);
    runBtn.disabled = false;
  }
}

loadCatalog();
