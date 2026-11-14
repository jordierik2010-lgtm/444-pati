import { useEffect, useMemo, useRef, useState } from "react";
import { api, errText, needsAdmin, onEvent, pickFolder, type BackupView, type Level, type OpView, type Plan, type Report } from "../services/api";
import { Bar, Modal, Page, Spinner, useToast } from "../components/ui";

type Stage = "idle" | "review" | "restore" | "running" | "admin" | "done" | "confirm-reboot";
const LV: Record<Level, string> = { info: "INFO", warning: "AVISO", danger: "PELIGRO", incompatible: "NO COMPATIBLE" };
const RISKY = (l: Level) => l === "danger" || l === "incompatible";
const category = (o: OpView) => { const l = o.location.toLowerCase();
  return l.includes("\\mouse") ? "Mouse" : l.includes("accessibility") ? "Input" : l.includes("\\keyboard") ? "Keyboard" : l.includes("kbdclass") ? "Input" : l.includes("afd") ? "Network" : "System"; };
const CATS = ["Mouse", "Keyboard", "Input", "Network", "System"];

function VideoPlayer() {
  const [src, setSrc] = useState<string | null>(null); const ref = useRef<HTMLVideoElement>(null); const objUrl = useRef<string | null>(null);
  useEffect(() => {
    fetch("/movement.mp4", { method: "HEAD" }).then(r => { if (r.ok && (r.headers.get("content-type") || "").startsWith("video")) setSrc("/movement.mp4"); }).catch(() => {});
    return () => { if (objUrl.current) URL.revokeObjectURL(objUrl.current); };
  }, []);
  const pick = (f?: File) => { if (!f) return; if (objUrl.current) URL.revokeObjectURL(objUrl.current); objUrl.current = URL.createObjectURL(f); setSrc(objUrl.current); };
  return (
    <div className="video">
      {src ? <video ref={ref} src={src} controls preload="metadata" playsInline /> :
        <div className="empty"><div><b style={{ color: "var(--text)" }}>MOVEMENT PREVIEW</b><br />Aún no hay vídeo de demostración.</div>
          <label className="btn primary">Seleccionar vídeo<input type="file" accept="video/*" hidden onChange={e => pick(e.target.files?.[0])} /></label>
          <small>Para incluirlo en la app, copia el archivo a <code>public/movement.mp4</code> y recompila.</small></div>}
    </div>
  );
}

export default function Movement() {
  const toast = useToast();
  const [plan, setPlan] = useState<Plan | null>(null); const [sel, setSel] = useState<Set<string>>(new Set()); const [ack, setAck] = useState(false);
  const [packs, setPacks] = useState<Set<string>>(new Set(["444CFG"]));
  const [backup, setBackup] = useState<BackupView | null>(null);
  const [stage, setStage] = useState<Stage>("idle"); const [mode, setMode] = useState<"apply" | "restore">("apply");
  const [prog, setProg] = useState(0); const [report, setReport] = useState<Report | null>(null); const [busy, setBusy] = useState(false);
  const loadBackup = () => api.backupInfo().then(setBackup).catch(() => setBackup(null));
  useEffect(() => { loadBackup(); api.plan().then(setPlan).catch(e => toast(errText(e), "err")); const u = onEvent<{ done: number; total: number }>("movement-progress", p => setProg(p.total ? p.done / p.total : 0)); return () => { u.then(f => f()); }; }, []);

  const ops = plan?.ops ?? [];
  const packNames = useMemo(() => Array.from(new Set(ops.map(o => o.pack))), [ops]);
  const visible = useMemo(() => ops.filter(o => packs.has(o.pack)), [ops, packs]);
  const chosen = useMemo(() => visible.filter(o => sel.has(o.id)), [visible, sel]);
  // Conflicts are recomputed for the packs currently enabled (display only; the backend applies exactly the confirmed ids in order).
  const conflicts = useMemo(() => {
    const ids = new Set(visible.map(o => o.id));
    return (plan?.conflicts ?? []).map(c => {
      const es = c.entries.filter(e => ids.has(e.op_id)); if (es.length < 2) return null;
      return { ...c, entries: es, kind: (es.every(e => e.value === es[0].value) ? "duplicate" : "conflict") as "duplicate" | "conflict", winner: es[es.length - 1].op_id };
    }).filter((c): c is NonNullable<typeof c> => c !== null);
  }, [plan, visible]);
  const togglePack = (name: string) => {
    // One pack per operation: mixing competing input/keyboard tweaks is confusing.
    setPacks(new Set([name]));
    setSel(new Set(ops.filter(o => o.pack === name && o.default_selected).map(o => o.id)));
    setAck(false);
  };
  const risky = chosen.some(o => RISKY(o.level));
  const hasBackup = !!backup && (backup.rows.length > 0 || backup.created_keys > 0);

  const openReview = async () => {
    setBusy(true);
    try { const p = await api.plan(); setPlan(p); setPacks(new Set(["444CFG"])); setSel(new Set(p.ops.filter(o => o.pack === "444CFG" && o.default_selected).map(o => o.id))); setAck(false); setMode("apply"); setStage("review"); }
    catch (e) { toast(errText(e), "err"); } finally { setBusy(false); }
  };
  const toggle = (id: string) => setSel(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const run = async () => {
    setStage("running"); setProg(0);
    try {
      const r = mode === "apply" ? await api.applyMovement(chosen.map(o => o.id), ack) : await api.restoreMovement();
      setReport(r); setStage("done"); loadBackup();
    } catch (e) { if (needsAdmin(e)) setStage("admin"); else { toast(errText(e), "err"); setStage("idle"); } }
  };
  const exportRegs = async () => { const d = await pickFolder(); if (!d) return; try { const r = await api.exportRegs(d); toast(r.join(" · "), "ok"); } catch (e) { toast(errText(e), "err"); } };
  const close = () => setStage("idle");
  const win = plan?.windows_ok !== false;

  return (
    <Page kicker="Optimización" title="Movement" lead="Optimizaciones de entrada, ratón, teclado y configuraciones compatibles del sistema. Se aplican tus regedits originales (packs 444CFG, EREN y GODLEAK), sin modificar ningún valor.">
      <div className="sect">VISTA PREVIA</div>
      <VideoPlayer />
      <div className="sect">QUÉ MODIFICA</div>
      <div className="chips">{CATS.map(c => { const n = ops.filter(o => category(o) === c).length; return <span key={c} className={`chip ${n ? "" : "off"}`}>{c}{n ? ` · ${n}` : ""}</span>; })}</div>
      <p className="lead" style={{ marginTop: 10, fontSize: 12 }}>Antes de aplicar verás cada modificación con su valor exacto, los conflictos entre archivos y los valores incompatibles o peligrosos. No se prometen mejoras de FPS, ping o precisión: no se han medido.</p>
      {!win && <div className="msg err">Esta versión de Windows no es compatible.</div>}
      <div className="col" style={{ marginTop: 18 }}>
        <button className="btn primary big" disabled={!win || busy || !plan} onClick={openReview}>{busy ? <Spinner /> : "▷ APLICAR MOVEMENT TWEAK"}</button>
        <button className="btn big" disabled={!hasBackup} title={hasBackup ? "" : "No hay cambios aplicados que restaurar"} onClick={() => { loadBackup(); setMode("restore"); setStage("restore"); }}>↺ RESTAURAR ORIGINAL</button>
        <button className="btn sm" style={{ alignSelf: "flex-start" }} onClick={exportRegs}>Exportar los .reg originales…</button>
      </div>

      {stage === "review" && plan && (
        <Modal wide title="Revisión de cambios" actions={<>
          <span className="mini" style={{ marginRight: "auto" }}>{chosen.length} de {visible.length} operaciones seleccionadas</span>
          <button className="btn" onClick={close}>Cancelar</button>
          <button className="btn primary" disabled={chosen.length === 0 || (risky && !ack)} onClick={run}>Aplicar {chosen.length} confirmadas</button></>}>
          <p style={{ color: "#aab2d0", marginTop: 0 }}>Se creará una copia de seguridad de los valores actuales (incluida la ausencia de la clave) <b>antes</b> de escribir. Se aplicará en el orden original (archivo a archivo, línea a línea) y solo lo marcado. Los valores se escriben exactamente como están en los archivos.</p>

          <div className="sect">PACKS DE REGEDITS (cada uno tal cual, sin modificar)</div>
          <div className="row" style={{ marginBottom: 8 }}>{packNames.map(n => <label key={n} className="chip" style={{ cursor: "pointer", display: "flex", gap: 8, alignItems: "center" }}>
            <input className="cb" type="radio" name="movement-pack" checked={packs.has(n)} onChange={() => togglePack(n)} />{n} · {plan.files.filter(f => f.pack === n).length} archivos · {ops.filter(o => o.pack === n).length} ops</label>)}</div>
          <div className="msg warn" style={{ marginBottom: 8 }}>Selecciona un único pack. Si ya aplicaste otro, usa RESTAURAR ORIGINAL antes de cambiar para evitar mezclar configuraciones.</div>

          <details><summary>Archivos originales ({plan.files.length}) — comprobación de integridad</summary>
            <table><thead><tr><th>ARCHIVO</th><th>PACK</th><th>CODIFICACIÓN</th><th>OPS</th><th>SHA-256</th></tr></thead><tbody>{plan.files.map(f => <tr key={f.n}>
              <td>{f.name}<div className="mini">{f.size} bytes</div></td><td>{f.pack}</td><td>{f.encoding}</td><td>{f.ops}</td><td className="mini">{f.sha256.slice(0, 16)}…</td></tr>)}</tbody></table>
            {plan.files.some(f => f.foreign.length) && <div className="msg warn" style={{ marginTop: 8 }}>Texto ajeno encontrado (no es una modificación del Registro): {plan.files.flatMap(f => f.foreign.map(x => `${f.name}:${x.line} «${x.text}»`)).join(" · ")}. Se conserva en los archivos pero <b>no se ejecuta ni se aplica</b>.</div>}
            {plan.files.some(f => f.errors.length) && <div className="msg err" style={{ marginTop: 8 }}>{plan.files.flatMap(f => f.errors.map(e => `${f.name}: ${e}`)).join(" · ")}</div>}
          </details>

          {conflicts.length > 0 && <>
            <div className="sect">CONFLICTOS ENTRE ARCHIVOS</div>
            <div className="msg warn" style={{ marginBottom: 8 }}>Varios archivos escriben el mismo valor. Se aplican en orden, así que <b>prevalece el último</b>. Los duplicados con el mismo valor son inofensivos; los conflictos cambian el resultado final.</div>
            <div className="scroll"><table><thead><tr><th>VALOR</th><th>TIPO</th><th>ARCHIVOS Y VALORES (ORDEN DE APLICACIÓN)</th></tr></thead><tbody>
              {conflicts.map((c, i) => <tr key={i} className={c.kind === "conflict" ? "row-danger" : ""}>
                <td>{c.name}<div className="mini">{c.location}</div></td>
                <td><span className={`lv ${c.kind === "conflict" ? "danger" : "info"}`}>{c.kind === "conflict" ? "CONFLICTO" : "DUPLICADO"}</span></td>
                <td>{c.entries.map(e => <div key={e.op_id} className="mini">{e.op_id === c.winner ? "★ " : ""}{e.file_name}:{e.line} → <code>{e.value}</code></div>)}</td></tr>)}</tbody></table></div></>}

          <div className="sect">MODIFICACIONES EN ORDEN ORIGINAL</div>
          <div className="row" style={{ marginBottom: 8 }}>
            <button className="btn sm" onClick={() => setSel(new Set(visible.filter(o => o.default_selected).map(o => o.id)))}>Solo recomendadas</button>
            <button className="btn sm" onClick={() => setSel(new Set(visible.map(o => o.id)))}>Todas (incluye peligrosas)</button>
            <button className="btn sm" onClick={() => setSel(new Set())}>Ninguna</button></div>
          <div className="scroll" style={{ maxHeight: 360 }}><table><thead><tr><th></th><th>#</th><th>ORIGEN</th><th>CLAVE / VALOR</th><th>ACTUAL → NUEVO (EXACTO)</th></tr></thead><tbody>
            {visible.map((o, i) => <tr key={o.id} className={`row-${o.level}`}>
              <td><input className="cb" type="checkbox" checked={sel.has(o.id)} onChange={() => toggle(o.id)} aria-label={`Aplicar ${o.name}`} /></td>
              <td>{i + 1}</td><td className="mini">{o.file_name}<br />línea {o.line}</td>
              <td><div className="mini">{o.location}</div><b>{o.name}</b>{o.needs_admin && <> <span className="tag">ADMIN</span></>}
                {o.findings.filter(f => f.level !== "info" || o.level === "info").slice(0, 4).map((f, i) => <div key={i}><span className={`lv ${f.level}`}>{LV[f.level]}</span><span className="mini">{f.text}</span></div>)}</td>
              <td><div className="mini">{o.current}</div><div>→ <code>{o.value}</code></div></td></tr>)}</tbody></table></div>

          {chosen.some(o => o.needs_admin) && !plan.elevated && <div className="msg warn" style={{ marginTop: 10 }}>Hay ajustes en HKLM: se te pedirá reabrir la app como administrador.</div>}
          {risky && <label className="msg err" style={{ display: "flex", gap: 10, marginTop: 12, cursor: "pointer" }}><input className="cb" type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />
            <span>Has seleccionado ajustes <b>incompatibles con Windows o potencialmente peligrosos</b>. Entiendo los riesgos y confirmo expresamente que se apliquen tal cual están en los archivos. Puedo deshacerlo con RESTAURAR ORIGINAL.</span></label>}
        </Modal>)}

      {stage === "restore" && (
        <Modal wide title="Restaurar configuración anterior" actions={<><button className="btn" onClick={close}>Cancelar</button><button className="btn primary" onClick={run}>Restaurar</button></>}>
          <p style={{ color: "#aab2d0", marginTop: 0 }}>Se recuperarán los valores reales guardados antes de aplicar. Los valores que no existían se eliminarán, y se borrarán las claves que creó la aplicación si quedan vacías.</p>
          <div className="scroll"><table><thead><tr><th>CLAVE / VALOR</th><th>SE RESTAURARÁ A</th></tr></thead><tbody>
            {backup?.rows.map((r, i) => <tr key={i}><td><div className="mini">{r.location}</div>{r.name}</td><td><code>{r.original}</code></td></tr>)}</tbody></table></div>
        </Modal>)}

      {stage === "running" && <Modal title={mode === "apply" ? "Aplicando…" : "Restaurando…"} actions={null}><div className="row" style={{ marginBottom: 10 }}><Spinner /> Escribiendo y verificando cada operación</div><Bar value={prog} /></Modal>}

      {stage === "admin" && <Modal title="Permisos de administrador" actions={<><button className="btn" onClick={close}>Cancelar</button><button className="btn primary" onClick={() => api.relaunchAdmin().catch(e => toast(errText(e), "err"))}>Reabrir como administrador</button></>}>
        <p style={{ color: "#aab2d0" }}>Hay valores en HKLM que requieren administrador. Windows pedirá confirmación (UAC). Tras reabrir, vuelve a pulsar el botón; no se ha modificado nada todavía.</p></Modal>}

      {stage === "done" && report && (
        <Modal wide title={report.all_ok ? (mode === "apply" ? "444CFG — OPTIMIZACIÓN COMPLETADA" : "444CFG — RESTAURACIÓN COMPLETADA") : "Completado con errores"}
          actions={report.reboot_recommended ? <><button className="btn" onClick={close}>REINICIAR MÁS TARDE</button><button className="btn primary" onClick={() => setStage("confirm-reboot")}>REINICIAR AHORA</button></> : <button className="btn primary" onClick={close}>Cerrar</button>}>
          {report.reboot_recommended && <p style={{ color: "#aab2d0", marginTop: 0 }}>Algunos cambios pueden requerir reiniciar Windows para aplicarse completamente.</p>}
          {!report.all_ok && <div className="msg err" style={{ marginBottom: 8 }}>{report.results.filter(r => !r.ok).length} operaciones fallaron; las demás se aplicaron y verificaron.</div>}
          <div className="scroll"><table><tbody>{report.results.map(r => <tr key={r.id}><td>{r.ok ? "✓" : "✕"}</td><td><div className="mini">{r.location}</div>{r.name} → <code>{r.value}</code>{r.error && <div className="msg err" style={{ marginTop: 4 }}>{r.error}</div>}</td></tr>)}</tbody></table></div>
        </Modal>)}

      {stage === "confirm-reboot" && <Modal title="¿Reiniciar Windows?" actions={<><button className="btn" onClick={close}>Cancelar</button><button className="btn primary" onClick={() => { api.restartWindows().then(() => toast("Reinicio en 30 s. Para cancelarlo: shutdown /a", "info")).catch(e => toast(errText(e), "err")); close(); }}>Sí, reiniciar</button></>}>
        <p style={{ color: "#aab2d0" }}>Guarda tu trabajo y cierra programas. El equipo se reiniciará en 30 segundos (cancelable con <code>shutdown /a</code>).</p></Modal>}
    </Page>
  );
}
