// SWK Assistant — sends due follow-ups and Sir's replies as Web Push notifications.
// Called every minute by pg_cron (only when something is waiting). Authenticated by a shared secret.
import webpush from "npm:web-push@3.6.7";
import { createClient } from "npm:@supabase/supabase-js@2";

const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
let cfg: { public: string; private: string; secret: string; subject: string } | null = null;

const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (!cfg) {
    const { data, error } = await sb.rpc("swk_push_config");
    if (error || !data?.private) return json({ error: "config", detail: error?.message }, 500);
    cfg = data;
    webpush.setVapidDetails(cfg!.subject, cfg!.public, cfg!.private);
  }
  if (req.headers.get("x-cron-secret") !== cfg!.secret) return json({ error: "unauthorized" }, 401);

  let body: any = {};
  try { body = await req.json(); } catch (_) { /* empty */ }

  // diagnostics: send one notification to a given subscription
  if (body.probe) {
    try {
      const r = await webpush.sendNotification(body.probe, JSON.stringify({ title: "SWK test", body: "Probe" }), { TTL: 60 });
      return json({ ok: true, status: r.statusCode });
    } catch (e: any) {
      return json({ ok: false, status: e?.statusCode ?? null, message: String(e?.body || e?.message || e).slice(0, 300) });
    }
  }

  const { data: queue, error } = await sb.rpc("swk_push_queue");
  if (error) return json({ error: error.message }, 500);

  const fDone: number[] = [], mDone: number[] = [], dead = new Set<string>();
  let sent = 0, failed = 0;
  await Promise.all((queue || []).map(async (item: any) => {
    await Promise.all((item.subs || []).map(async (s: any) => {
      const payload = JSON.stringify({ title: item.title, body: item.body, tag: item.tag, url: s.url || "./" });
      try {
        await webpush.sendNotification({ endpoint: s.endpoint, keys: s.keys }, payload, { TTL: 86400, urgency: "high" });
        sent++;
      } catch (e: any) {
        failed++;
        if (e?.statusCode === 404 || e?.statusCode === 410) dead.add(s.endpoint);
      }
    }));
    (item.kind === "followup" ? fDone : mDone).push(item.id);
  }));

  if (fDone.length || mDone.length || dead.size) {
    await sb.rpc("swk_push_mark", { p_followups: fDone, p_messages: mDone, p_dead: [...dead] });
  }
  return json({ ok: true, items: (queue || []).length, sent, failed, dead: dead.size });
});
