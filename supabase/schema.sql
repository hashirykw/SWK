-- ════════════════════════════════════════════════════════════════════
--  SWK Solutions · Chatbot backend (Supabase / Postgres)
--  Tables are locked with RLS (no direct access). Everything goes
--  through SECURITY DEFINER functions:
--    • student functions are gated by a private per-student token
--    • admin functions are gated by Sir's passcode (bcrypt-hashed)
-- ════════════════════════════════════════════════════════════════════

create extension if not exists pgcrypto with schema extensions;

-- ─── TABLES ─────────────────────────────────────────────────────────
create table if not exists public.swk_settings (
  key   text primary key,
  value jsonb not null
);

create table if not exists public.swk_lectures (
  id          uuid primary key default gen_random_uuid(),
  level       text not null default 'Any',            -- 'O Level' | 'A Level' | 'Any'
  subject     text not null default 'Mathematics',
  title       text not null,
  teacher     text not null default 'Sir Waqas Khan',
  url         text not null,
  passcode    text,
  is_default  boolean not null default false,
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);

create table if not exists public.swk_leads (
  id                uuid primary key default gen_random_uuid(),
  token             uuid not null unique default gen_random_uuid(),
  name              text not null,
  phone             text not null,
  email             text,
  level             text,
  subject           text,
  campus            text,
  school            text,
  grade             text,
  mode              text,
  intent            text not null default 'lecture',   -- lecture | admission | fee | talk | question
  status            text not null default 'new',        -- new | watched | contacted | interested | call_requested | enrolled | lost
  join_when         text,
  notes             text,
  lecture_id        uuid references public.swk_lectures(id) on delete set null,
  lecture_opened_at timestamptz,
  lecture_opens     int not null default 0,
  unread_admin      int not null default 0,
  unread_student    int not null default 0,
  last_message_at   timestamptz not null default now(),
  last_seen_at      timestamptz not null default now(),
  created_at        timestamptz not null default now()
);
create index if not exists swk_leads_created_idx on public.swk_leads(created_at desc);
create index if not exists swk_leads_lastmsg_idx on public.swk_leads(last_message_at desc);

create table if not exists public.swk_messages (
  id          bigserial primary key,
  lead_id     uuid not null references public.swk_leads(id) on delete cascade,
  sender      text not null check (sender in ('student','bot','admin','followup','system')),
  body        text not null,
  meta        jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now()
);
create index if not exists swk_messages_lead_idx on public.swk_messages(lead_id, id);

create table if not exists public.swk_followup_templates (
  id             serial primary key,
  step           int not null,
  delay_hours    int not null,
  title          text not null,
  body           text not null,
  quick_replies  jsonb not null default '[]'::jsonb,
  active         boolean not null default true
);

create table if not exists public.swk_followups (
  id             bigserial primary key,
  lead_id        uuid not null references public.swk_leads(id) on delete cascade,
  template_id    int references public.swk_followup_templates(id) on delete set null,
  title          text not null,
  body           text not null,
  quick_replies  jsonb not null default '[]'::jsonb,
  due_at         timestamptz not null,
  delivered_at   timestamptz,
  responded_at   timestamptz,
  response       text,
  cancelled      boolean not null default false,
  created_at     timestamptz not null default now()
);
create index if not exists swk_followups_due_idx on public.swk_followups(lead_id, due_at);

create table if not exists public.swk_events (
  id          bigserial primary key,
  lead_id     uuid references public.swk_leads(id) on delete cascade,
  visitor     text,
  type        text not null,
  data        jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now()
);
create index if not exists swk_events_type_idx on public.swk_events(type, created_at);
create index if not exists swk_events_lead_idx on public.swk_events(lead_id);
create index if not exists swk_leads_lecture_idx on public.swk_leads(lecture_id);
create index if not exists swk_followups_tpl_idx on public.swk_followups(template_id);
alter table public.swk_lectures add column if not exists archived boolean not null default false;
alter table public.swk_followup_templates add column if not exists archived boolean not null default false;

alter table public.swk_settings           enable row level security;
alter table public.swk_lectures           enable row level security;
alter table public.swk_leads              enable row level security;
alter table public.swk_messages           enable row level security;
alter table public.swk_followup_templates enable row level security;
alter table public.swk_followups          enable row level security;
alter table public.swk_events             enable row level security;

-- ─── HELPERS ────────────────────────────────────────────────────────
create or replace function public.swk_clean(t text, maxlen int default 300)
returns text language sql immutable set search_path = public as $$
  select nullif(left(btrim(coalesce(t,'')), maxlen), '')
$$;

create or replace function public.swk_first_name(n text)
returns text language sql immutable set search_path = public as $$
  select split_part(btrim(coalesce(n,'')), ' ', 1)
$$;

create or replace function public.swk_fill(body text, l public.swk_leads)
returns text language sql stable set search_path = public as $$
  select replace(replace(replace(replace(body,
    '{first_name}', coalesce(public.swk_first_name(l.name),'there')),
    '{name}', coalesce(l.name,'')),
    '{level}', coalesce(l.level,'')),
    '{subject}', coalesce(l.subject,''))
$$;

create or replace function public.swk_is_admin(p_pass text)
returns boolean language plpgsql stable security definer
set search_path = public, extensions as $$
declare h text;
begin
  select value->>'hash' into h from swk_settings where key = 'admin_pass';
  if h is null or p_pass is null or length(p_pass) < 4 then return false; end if;
  return extensions.crypt(p_pass, h) = h;
end $$;

create or replace function public.swk_require_admin(p_pass text)
returns void language plpgsql stable security definer
set search_path = public, extensions as $$
begin
  if not public.swk_is_admin(p_pass) then
    perform pg_sleep(0.6);
    raise exception 'unauthorized' using errcode = '28000';
  end if;
end $$;

create or replace function public.swk_msg_json(m public.swk_messages)
returns jsonb language sql stable set search_path = public as $$
  select jsonb_build_object('id', m.id, 'sender', m.sender, 'body', m.body,
                            'meta', m.meta, 'at', m.created_at)
$$;

-- ═══ STUDENT-FACING FUNCTIONS (anon) ════════════════════════════════

-- Lightweight analytics (chat opened, option clicked, etc.)
create or replace function public.swk_log_event(p_visitor text, p_token uuid, p_type text, p_data jsonb default '{}'::jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare lid uuid;
begin
  if p_type is null or length(p_type) > 40 then return; end if;
  if p_token is not null then select id into lid from swk_leads where token = p_token; end if;
  insert into swk_events(lead_id, visitor, type, data)
  values (lid, left(p_visitor, 64), p_type, coalesce(p_data, '{}'::jsonb));
end $$;

-- Create (or update) a lead from a chatbot form. Returns token + lecture.
create or replace function public.swk_submit_form(p_token uuid, p jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  l swk_leads; lec swk_lectures; t swk_followup_templates;
  v_intent text := coalesce(swk_clean(p->>'intent', 20), 'lecture');
  v_level  text := swk_clean(p->>'level', 20);
  v_subject text := coalesce(swk_clean(p->>'subject', 60), 'Mathematics');
  v_name text := swk_clean(p->>'name', 80);
  v_phone text := swk_clean(regexp_replace(coalesce(p->>'phone',''), '[^0-9+]', '', 'g'), 20);
  is_new boolean := false;
  summary text;
begin
  if v_name is null or v_phone is null or length(v_phone) < 10 then
    raise exception 'Please enter your name and a valid phone number';
  end if;

  if p_token is not null then
    select * into l from swk_leads where token = p_token;
  end if;

  if l.id is null then
    insert into swk_leads(name, phone, email, level, subject, campus, school, grade, mode, intent)
    values (v_name, v_phone, swk_clean(p->>'email', 120), v_level, v_subject,
            swk_clean(p->>'campus', 60), swk_clean(p->>'school', 120),
            swk_clean(p->>'grade', 40), swk_clean(p->>'mode', 30), v_intent)
    returning * into l;
    is_new := true;
  else
    update swk_leads set
      name = v_name, phone = v_phone,
      email   = coalesce(swk_clean(p->>'email', 120), email),
      level   = coalesce(v_level, level),
      subject = coalesce(v_subject, subject),
      campus  = coalesce(swk_clean(p->>'campus', 60), campus),
      school  = coalesce(swk_clean(p->>'school', 120), school),
      grade   = coalesce(swk_clean(p->>'grade', 40), grade),
      mode    = coalesce(swk_clean(p->>'mode', 30), mode),
      intent  = v_intent,
      last_seen_at = now()
    where id = l.id returning * into l;
  end if;

  summary := 'Form submitted — ' || initcap(v_intent)
          || coalesce(' · ' || l.level, '') || coalesce(' · ' || l.subject, '')
          || coalesce(' · ' || l.campus, '') || coalesce(' · ' || l.mode, '');
  insert into swk_messages(lead_id, sender, body, meta)
  values (l.id, 'system', summary, jsonb_build_object('form', p));

  if v_intent = 'lecture' then
    select * into lec from swk_lectures
     where active and (level = v_level or level = 'Any')
       and (subject = v_subject or subject = 'Any')
     order by (level = v_level) desc, (subject = v_subject) desc, created_at desc limit 1;
    if lec.id is null then
      select * into lec from swk_lectures where active and is_default order by created_at desc limit 1;
    end if;
    if lec.id is not null then
      update swk_leads set lecture_id = lec.id where id = l.id;
      insert into swk_messages(lead_id, sender, body, meta)
      values (l.id, 'bot', 'Demo lecture delivered: ' || lec.title,
              jsonb_build_object('lecture_id', lec.id));
    end if;
  end if;

  -- schedule follow-ups once per lead
  if not exists (select 1 from swk_followups where lead_id = l.id and template_id is not null) then
    for t in select * from swk_followup_templates where active order by step loop
      insert into swk_followups(lead_id, template_id, title, body, quick_replies, due_at)
      values (l.id, t.id, t.title, swk_fill(t.body, l), t.quick_replies,
              now() + make_interval(hours => t.delay_hours));
    end loop;
  end if;

  insert into swk_events(lead_id, type, data) values (l.id, 'form_submitted', jsonb_build_object('intent', v_intent, 'new', is_new));
  update swk_leads set unread_admin = unread_admin + 1, last_message_at = now() where id = l.id;

  return jsonb_build_object(
    'token', l.token,
    'name', l.name,
    'lecture', case when lec.id is null then null else jsonb_build_object(
        'id', lec.id, 'title', lec.title, 'teacher', lec.teacher, 'level', lec.level,
        'subject', lec.subject, 'url', lec.url, 'passcode', lec.passcode) end);
end $$;

-- Student opened the lecture link
create or replace function public.swk_lecture_opened(p_token uuid)
returns void language plpgsql security definer set search_path = public as $$
declare l swk_leads;
begin
  select * into l from swk_leads where token = p_token;
  if l.id is null then return; end if;
  update swk_leads set
    lecture_opened_at = coalesce(lecture_opened_at, now()),
    lecture_opens = lecture_opens + 1,
    status = case when status = 'new' then 'watched' else status end
  where id = l.id;
  insert into swk_events(lead_id, type) values (l.id, 'lecture_opened');
end $$;

-- Student sends a message (free text, or a quick-reply to a follow-up)
create or replace function public.swk_send(p_token uuid, p_body text, p_meta jsonb default '{}'::jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare l swk_leads; m swk_messages; v_body text := swk_clean(p_body, 2000); fid bigint;
begin
  select * into l from swk_leads where token = p_token;
  if l.id is null then raise exception 'unknown session'; end if;
  if v_body is null then raise exception 'empty message'; end if;

  -- crude flood guard: max 30 messages / 10 min
  if (select count(*) from swk_messages where lead_id = l.id and sender = 'student'
        and created_at > now() - interval '10 minutes') >= 30 then
    raise exception 'Too many messages, please wait a moment';
  end if;

  insert into swk_messages(lead_id, sender, body, meta)
  values (l.id, 'student', v_body, coalesce(p_meta, '{}'::jsonb)) returning * into m;

  fid := nullif(p_meta->>'followup_id', '')::bigint;
  if fid is not null then
    update swk_followups set responded_at = coalesce(responded_at, now()), response = v_body
     where id = fid and lead_id = l.id;
    insert into swk_events(lead_id, type, data) values (l.id, 'followup_reply', jsonb_build_object('followup_id', fid, 'reply', v_body));
  end if;

  if p_meta ? 'join_when' then
    update swk_leads set join_when = swk_clean(p_meta->>'join_when', 40),
      status = case when status in ('new','watched','contacted') then 'interested' else status end
     where id = l.id;
  end if;
  if (p_meta->>'call_request')::boolean is true then
    update swk_leads set status = case when status <> 'enrolled' then 'call_requested' else status end where id = l.id;
  end if;
  if (p_meta->>'not_interested')::boolean is true then
    update swk_leads set status = case when status in ('new','watched') then 'lost' else status end where id = l.id;
  end if;

  -- the chatbot already answered it from the FAQ: store that answer too, don't ping Sir
  if swk_clean(p_meta->>'bot_reply', 2000) is not null then
    insert into swk_messages(lead_id, sender, body, meta)
    values (l.id, 'bot', swk_clean(p_meta->>'bot_reply', 2000), jsonb_build_object('auto', true));
  end if;

  update swk_leads set
    unread_admin = unread_admin + case when (p_meta->>'auto_answered')::boolean is true then 0 else 1 end,
    last_message_at = now(), last_seen_at = now()
   where id = l.id;
  return swk_msg_json(m);
end $$;

-- Poll: new messages since id, deliver due follow-ups
create or replace function public.swk_sync(p_token uuid, p_since bigint default 0)
returns jsonb language plpgsql security definer set search_path = public as $$
declare l swk_leads; f swk_followups; msgs jsonb;
begin
  select * into l from swk_leads where token = p_token;
  if l.id is null then return jsonb_build_object('ok', false); end if;

  for f in select * from swk_followups
            where lead_id = l.id and not cancelled and delivered_at is null and due_at <= now()
            order by due_at loop
    insert into swk_messages(lead_id, sender, body, meta, created_at)
    values (l.id, 'followup', f.body,
            jsonb_build_object('followup_id', f.id, 'title', f.title, 'quick_replies', f.quick_replies),
            now());
    update swk_followups set delivered_at = now() where id = f.id;
    update swk_leads set unread_student = unread_student + 1 where id = l.id;
    insert into swk_events(lead_id, type, data) values (l.id, 'followup_delivered', jsonb_build_object('followup_id', f.id));
  end loop;

  update swk_leads set last_seen_at = now() where id = l.id;

  select coalesce(jsonb_agg(swk_msg_json(m) order by m.id), '[]'::jsonb) into msgs
    from swk_messages m
   where m.lead_id = l.id and m.id > coalesce(p_since, 0)
     and m.sender in ('admin','followup');

  select * into l from swk_leads where id = l.id;
  return jsonb_build_object('ok', true, 'messages', msgs, 'unread', l.unread_student,
                            'name', l.name, 'status', l.status);
end $$;

-- Full thread for a returning student
create or replace function public.swk_history(p_token uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare l swk_leads; lec swk_lectures; msgs jsonb;
begin
  select * into l from swk_leads where token = p_token;
  if l.id is null then return jsonb_build_object('ok', false); end if;
  select * into lec from swk_lectures where id = l.lecture_id;
  select coalesce(jsonb_agg(swk_msg_json(m) order by m.id), '[]'::jsonb) into msgs
    from (select * from swk_messages where lead_id = l.id and sender <> 'system'
          order by id desc limit 120) m;
  return jsonb_build_object('ok', true, 'name', l.name, 'messages', msgs,
    'lecture', case when lec.id is null then null else jsonb_build_object(
        'id', lec.id, 'title', lec.title, 'teacher', lec.teacher, 'level', lec.level,
        'subject', lec.subject, 'url', lec.url, 'passcode', lec.passcode) end);
end $$;

create or replace function public.swk_mark_read(p_token uuid)
returns void language sql security definer set search_path = public as $$
  update swk_leads set unread_student = 0 where token = p_token
$$;

-- ═══ ADMIN FUNCTIONS (passcode) ═════════════════════════════════════

create or replace function public.swk_admin_login(p_pass text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  if not swk_is_admin(p_pass) then perform pg_sleep(0.8); return false; end if;
  return true;
end $$;

create or replace function public.swk_admin_set_pass(p_pass text, p_new text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  perform swk_require_admin(p_pass);
  if p_new is null or length(p_new) < 8 then raise exception 'New passcode must be at least 8 characters'; end if;
  update swk_settings set value = jsonb_build_object('hash', extensions.crypt(p_new, extensions.gen_salt('bf', 10)))
   where key = 'admin_pass';
  return true;
end $$;

create or replace function public.swk_admin_dashboard(p_pass text, p_days int default 14)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare d int := greatest(1, least(coalesce(p_days,14), 365)); since timestamptz; r jsonb;
begin
  perform swk_require_admin(p_pass);
  since := date_trunc('day', now() at time zone 'Asia/Karachi') at time zone 'Asia/Karachi' - make_interval(days => d - 1);
  select jsonb_build_object(
    'kpi', jsonb_build_object(
      'leads_total',   (select count(*) from swk_leads),
      'leads_period',  (select count(*) from swk_leads where created_at >= since),
      'leads_today',   (select count(*) from swk_leads where created_at >= date_trunc('day', now() at time zone 'Asia/Karachi') at time zone 'Asia/Karachi'),
      'watched',       (select count(*) from swk_leads where lecture_opened_at is not null and created_at >= since),
      'interested',    (select count(*) from swk_leads where status in ('interested','call_requested') and created_at >= since),
      'enrolled',      (select count(*) from swk_leads where status = 'enrolled' and created_at >= since),
      'unread',        (select coalesce(sum(unread_admin),0) from swk_leads),
      'chats_opened',  (select count(*) from swk_events where type = 'chat_opened' and created_at >= since),
      'fu_delivered',  (select count(*) from swk_followups f join swk_leads l on l.id=f.lead_id where f.delivered_at >= since),
      'fu_replied',    (select count(*) from swk_followups f where f.responded_at >= since),
      'fu_pending',    (select count(*) from swk_followups where not cancelled and delivered_at is null),
      'fu_due_now',    (select count(*) from swk_followups where not cancelled and responded_at is null and due_at <= now())
    ),
    'by_day', (select coalesce(jsonb_agg(jsonb_build_object('day', to_char(g.day,'YYYY-MM-DD'),
                 'leads', (select count(*) from swk_leads l where (l.created_at at time zone 'Asia/Karachi')::date = g.day),
                 'watched', (select count(*) from swk_events e where e.type='lecture_opened' and (e.created_at at time zone 'Asia/Karachi')::date = g.day),
                 'chats', (select count(*) from swk_events e where e.type='chat_opened' and (e.created_at at time zone 'Asia/Karachi')::date = g.day)
               ) order by g.day), '[]'::jsonb)
               from generate_series((now() at time zone 'Asia/Karachi')::date - (d-1), (now() at time zone 'Asia/Karachi')::date, interval '1 day') as g(day)),
    'by_intent', (select coalesce(jsonb_object_agg(k, c), '{}'::jsonb) from (select coalesce(intent,'—') k, count(*) c from swk_leads where created_at >= since group by 1) s),
    'by_level',  (select coalesce(jsonb_object_agg(k, c), '{}'::jsonb) from (select coalesce(level,'—') k, count(*) c from swk_leads where created_at >= since group by 1) s),
    'by_campus', (select coalesce(jsonb_object_agg(k, c), '{}'::jsonb) from (select coalesce(campus,'—') k, count(*) c from swk_leads where created_at >= since group by 1) s),
    'by_status', (select coalesce(jsonb_object_agg(k, c), '{}'::jsonb) from (select status k, count(*) c from swk_leads group by 1) s),
    'by_join',   (select coalesce(jsonb_object_agg(k, c), '{}'::jsonb) from (select join_when k, count(*) c from swk_leads where join_when is not null and created_at >= since group by 1) s),
    'options',   (select coalesce(jsonb_object_agg(k, c), '{}'::jsonb) from (select data->>'option' k, count(*) c from swk_events where type='option_clicked' and created_at >= since group by 1) s),
    'since', since
  ) into r;
  return r;
end $$;

create or replace function public.swk_admin_leads(p_pass text, p_search text default null, p_status text default null, p_limit int default 300)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare r jsonb; q text := nullif(btrim(coalesce(p_search,'')), '');
begin
  perform swk_require_admin(p_pass);
  select coalesce(jsonb_agg(x order by x->>'last_message_at' desc), '[]'::jsonb) into r from (
    select jsonb_build_object(
      'id', l.id, 'name', l.name, 'phone', l.phone, 'email', l.email, 'level', l.level,
      'subject', l.subject, 'campus', l.campus, 'school', l.school, 'grade', l.grade, 'mode', l.mode,
      'intent', l.intent, 'status', l.status, 'join_when', l.join_when, 'notes', l.notes,
      'lecture_opened_at', l.lecture_opened_at, 'lecture_opens', l.lecture_opens,
      'unread_admin', l.unread_admin, 'last_message_at', l.last_message_at,
      'last_seen_at', l.last_seen_at, 'created_at', l.created_at,
      'last_message', (select jsonb_build_object('sender', m.sender, 'body', left(m.body, 140), 'at', m.created_at)
                         from swk_messages m where m.lead_id = l.id and m.sender <> 'system' order by m.id desc limit 1),
      'next_followup', (select min(due_at) from swk_followups f where f.lead_id = l.id and not f.cancelled and f.delivered_at is null)
    ) x
    from swk_leads l
    where (q is null or l.name ilike '%'||q||'%' or l.phone ilike '%'||q||'%' or coalesce(l.school,'') ilike '%'||q||'%' or coalesce(l.email,'') ilike '%'||q||'%')
      and ((p_status is null or p_status = '') and l.status <> 'archived' or l.status = p_status)
    order by l.last_message_at desc
    limit greatest(1, least(coalesce(p_limit,300), 2000))
  ) s;
  return r;
end $$;

create or replace function public.swk_admin_thread(p_pass text, p_lead uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare r jsonb;
begin
  perform swk_require_admin(p_pass);
  update swk_leads set unread_admin = 0 where id = p_lead;
  select jsonb_build_object(
    'lead', (select to_jsonb(l) - 'token' from swk_leads l where l.id = p_lead),
    'lecture', (select to_jsonb(c) from swk_lectures c join swk_leads l on l.lecture_id = c.id where l.id = p_lead),
    'messages', (select coalesce(jsonb_agg(swk_msg_json(m) order by m.id), '[]'::jsonb) from swk_messages m where m.lead_id = p_lead),
    'followups', (select coalesce(jsonb_agg(to_jsonb(f) order by f.due_at), '[]'::jsonb) from swk_followups f where f.lead_id = p_lead),
    'events', (select coalesce(jsonb_agg(jsonb_build_object('type', e.type, 'data', e.data, 'at', e.created_at) order by e.id desc), '[]'::jsonb)
                 from (select * from swk_events where lead_id = p_lead order by id desc limit 40) e)
  ) into r;
  return r;
end $$;

create or replace function public.swk_admin_reply(p_pass text, p_lead uuid, p_body text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare m swk_messages; v text := swk_clean(p_body, 4000);
begin
  perform swk_require_admin(p_pass);
  if v is null then raise exception 'empty message'; end if;
  insert into swk_messages(lead_id, sender, body) values (p_lead, 'admin', v) returning * into m;
  update swk_leads set unread_student = unread_student + 1, last_message_at = now(),
    status = case when status in ('new','watched') then 'contacted' else status end
   where id = p_lead;
  return swk_msg_json(m);
end $$;

create or replace function public.swk_admin_update_lead(p_pass text, p_lead uuid, p jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare l swk_leads;
begin
  perform swk_require_admin(p_pass);
  update swk_leads set
    status = coalesce(swk_clean(p->>'status', 30), status),
    notes  = case when p ? 'notes' then swk_clean(p->>'notes', 4000) else notes end,
    join_when = case when p ? 'join_when' then swk_clean(p->>'join_when', 40) else join_when end
  where id = p_lead returning * into l;
  if p->>'status' in ('enrolled','lost','archived') then
    update swk_followups set cancelled = true where lead_id = p_lead and delivered_at is null;
  end if;
  return to_jsonb(l) - 'token';
end $$;

create or replace function public.swk_admin_delete_lead(p_pass text, p_lead uuid)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  perform swk_require_admin(p_pass);
  update swk_leads set status = 'archived', unread_admin = 0 where id = p_lead;
  update swk_followups set cancelled = true where lead_id = p_lead and delivered_at is null;
  return true;
end $$;

-- custom one-off follow-up from Sir
create or replace function public.swk_admin_schedule(p_pass text, p_lead uuid, p_body text, p_hours numeric default 0, p_quick jsonb default '[]'::jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare f swk_followups;
begin
  perform swk_require_admin(p_pass);
  if swk_clean(p_body, 2000) is null then raise exception 'empty follow-up'; end if;
  insert into swk_followups(lead_id, title, body, quick_replies, due_at)
  values (p_lead, 'Message from Sir', swk_clean(p_body, 2000), coalesce(p_quick,'[]'::jsonb),
          now() + make_interval(secs => greatest(0, coalesce(p_hours,0)) * 3600))
  returning * into f;
  return to_jsonb(f);
end $$;

create or replace function public.swk_admin_cancel_followup(p_pass text, p_id bigint)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  perform swk_require_admin(p_pass);
  update swk_followups set cancelled = true where id = p_id and delivered_at is null;
  return true;
end $$;

-- follow-up queue (due / upcoming / unanswered)
create or replace function public.swk_admin_followups(p_pass text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare r jsonb;
begin
  perform swk_require_admin(p_pass);
  select coalesce(jsonb_agg(x order by (x->>'due_at')), '[]'::jsonb) into r from (
    select to_jsonb(f) || jsonb_build_object('lead_name', l.name, 'phone', l.phone, 'level', l.level,
             'status', l.status, 'last_seen_at', l.last_seen_at) x
      from swk_followups f join swk_leads l on l.id = f.lead_id
     where not f.cancelled and f.responded_at is null
       and l.status not in ('enrolled','lost')
       and f.due_at <= now() + interval '7 days'
     order by f.due_at limit 500
  ) s;
  return r;
end $$;

create or replace function public.swk_admin_poll(p_pass text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  perform swk_require_admin(p_pass);
  return jsonb_build_object(
    'unread', (select coalesce(sum(unread_admin),0) from swk_leads),
    'last_student_msg', (select max(id) from swk_messages where sender = 'student'),
    'leads', (select count(*) from swk_leads));
end $$;

-- lectures CRUD
create or replace function public.swk_admin_lectures(p_pass text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  perform swk_require_admin(p_pass);
  return (select coalesce(jsonb_agg(to_jsonb(c) || jsonb_build_object(
            'sent', (select count(*) from swk_leads l where l.lecture_id = c.id),
            'opened', (select count(*) from swk_leads l where l.lecture_id = c.id and l.lecture_opened_at is not null))
          order by c.created_at), '[]'::jsonb) from swk_lectures c where not c.archived);
end $$;

create or replace function public.swk_admin_save_lecture(p_pass text, p jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare c swk_lectures; v_id uuid := nullif(p->>'id','')::uuid;
begin
  perform swk_require_admin(p_pass);
  if coalesce((p->>'delete')::boolean, false) and v_id is not null then
    update swk_lectures set archived = true, active = false, is_default = false where id = v_id; return '{}'::jsonb;
  end if;
  if (p->>'is_default')::boolean is true then update swk_lectures set is_default = false; end if;
  if v_id is null then
    insert into swk_lectures(level, subject, title, teacher, url, passcode, is_default, active)
    values (coalesce(swk_clean(p->>'level',20),'Any'), coalesce(swk_clean(p->>'subject',60),'Mathematics'),
            swk_clean(p->>'title',160), coalesce(swk_clean(p->>'teacher',80),'Sir Waqas Khan'),
            swk_clean(p->>'url',600), swk_clean(p->>'passcode',60),
            coalesce((p->>'is_default')::boolean,false), coalesce((p->>'active')::boolean,true))
    returning * into c;
  else
    update swk_lectures set
      level = coalesce(swk_clean(p->>'level',20), level), subject = coalesce(swk_clean(p->>'subject',60), subject),
      title = coalesce(swk_clean(p->>'title',160), title), teacher = coalesce(swk_clean(p->>'teacher',80), teacher),
      url = coalesce(swk_clean(p->>'url',600), url), passcode = swk_clean(p->>'passcode',60),
      is_default = coalesce((p->>'is_default')::boolean, is_default), active = coalesce((p->>'active')::boolean, active)
    where id = v_id returning * into c;
  end if;
  return to_jsonb(c);
end $$;

-- follow-up templates
create or replace function public.swk_admin_templates(p_pass text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  perform swk_require_admin(p_pass);
  return (select coalesce(jsonb_agg(to_jsonb(t) || jsonb_build_object(
            'delivered', (select count(*) from swk_followups f where f.template_id = t.id and f.delivered_at is not null),
            'replied', (select count(*) from swk_followups f where f.template_id = t.id and f.responded_at is not null))
          order by t.step), '[]'::jsonb) from swk_followup_templates t where not t.archived);
end $$;

create or replace function public.swk_admin_save_template(p_pass text, p jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare t swk_followup_templates; v_id int := nullif(p->>'id','')::int;
begin
  perform swk_require_admin(p_pass);
  if coalesce((p->>'delete')::boolean,false) and v_id is not null then
    update swk_followup_templates set archived = true, active = false where id = v_id; return '{}'::jsonb;
  end if;
  if v_id is null then
    insert into swk_followup_templates(step, delay_hours, title, body, quick_replies, active)
    values (coalesce((p->>'step')::int, 1 + (select coalesce(max(step),0) from swk_followup_templates)),
            greatest(1, coalesce((p->>'delay_hours')::int, 24)), coalesce(swk_clean(p->>'title',80),'Follow-up'),
            coalesce(swk_clean(p->>'body',2000),''), coalesce(p->'quick_replies','[]'::jsonb),
            coalesce((p->>'active')::boolean,true))
    returning * into t;
  else
    update swk_followup_templates set
      step = coalesce((p->>'step')::int, step), delay_hours = greatest(1, coalesce((p->>'delay_hours')::int, delay_hours)),
      title = coalesce(swk_clean(p->>'title',80), title), body = coalesce(swk_clean(p->>'body',2000), body),
      quick_replies = coalesce(p->'quick_replies', quick_replies), active = coalesce((p->>'active')::boolean, active)
    where id = v_id returning * into t;
  end if;
  return to_jsonb(t);
end $$;

-- ─── PERMISSIONS ────────────────────────────────────────────────────
revoke all on all tables in schema public from anon, authenticated;
revoke execute on all functions in schema public from public, anon, authenticated;
do $$ declare f text; begin
  foreach f in array array[
    'swk_log_event(text,uuid,text,jsonb)', 'swk_submit_form(uuid,jsonb)', 'swk_lecture_opened(uuid)',
    'swk_send(uuid,text,jsonb)', 'swk_sync(uuid,bigint)', 'swk_history(uuid)', 'swk_mark_read(uuid)',
    'swk_admin_login(text)', 'swk_admin_set_pass(text,text)', 'swk_admin_dashboard(text,int)',
    'swk_admin_leads(text,text,text,int)', 'swk_admin_thread(text,uuid)', 'swk_admin_reply(text,uuid,text)',
    'swk_admin_update_lead(text,uuid,jsonb)', 'swk_admin_delete_lead(text,uuid)',
    'swk_admin_schedule(text,uuid,text,numeric,jsonb)', 'swk_admin_cancel_followup(text,bigint)',
    'swk_admin_followups(text)', 'swk_admin_poll(text)', 'swk_admin_lectures(text)',
    'swk_admin_save_lecture(text,jsonb)', 'swk_admin_templates(text)', 'swk_admin_save_template(text,jsonb)'
  ] loop
    execute format('grant execute on function public.%s to anon, authenticated', f);
  end loop;
end $$;

-- ─── SEED ───────────────────────────────────────────────────────────
insert into public.swk_lectures(level, subject, title, teacher, url, passcode, is_default)
select 'Any', 'Mathematics', 'O / A Level Maths — Demo Lecture', 'Sir Waqas Khan',
       'https://zoom.us/clips/share/piVHafNVQJejRavJun0I-g', 'Swk@1273', true
where not exists (select 1 from public.swk_lectures);

insert into public.swk_followup_templates(step, delay_hours, title, body, quick_replies)
select * from (values
  (1, 24, 'How was the demo?',
   'Assalam-o-Alaikum {first_name}! Hope you got a chance to watch Sir Waqas Khan''s demo lecture. How did you find it?',
   '["Loved it","It was good","Haven''t watched yet","I have a question"]'::jsonb),
  (2, 48, 'When would you like to join?',
   '{first_name}, new {level} batches for Session 2026-27 are filling up (Group A / B / C) and Early Bird seats are limited. When would you like to start?',
   '["This week","Next week","This month","Send fee details","Not sure yet"]'::jsonb),
  (3, 120, 'Shall Sir''s team call you?',
   'Just checking in, {first_name} — would you like SWK''s team to call you and reserve a seat in the batch that suits you?',
   '["Yes, call me","WhatsApp me","Not now"]'::jsonb)
) v(step, delay_hours, title, body, quick_replies)
where not exists (select 1 from public.swk_followup_templates);

-- ═══ WEB PUSH (follow-ups + Sir's replies as phone/desktop notifications) ═══
-- Keys live in swk_settings('push') = {public, private, secret, subject}; set them directly in SQL, never in the repo.
-- Edge function: supabase/functions/swk-push (verify_jwt off, checks x-cron-secret).
create extension if not exists pg_net with schema extensions;
create extension if not exists pg_cron;
alter table public.swk_followups add column if not exists pushed_at timestamptz;
alter table public.swk_messages add column if not exists pushed_at timestamptz;
create table if not exists public.swk_push_subs (
  id bigserial primary key, lead_id uuid not null references public.swk_leads(id) on delete cascade,
  endpoint text not null unique, p256dh text not null, auth text not null, url text,
  dead boolean not null default false, created_at timestamptz not null default now(), updated_at timestamptz not null default now());
alter table public.swk_push_subs enable row level security;
-- functions: swk_save_push(token, sub) [anon]; swk_push_pending(), swk_push_queue(),
-- swk_push_mark(followups[], messages[], dead_endpoints[]), swk_push_config() [service_role only];
-- swk_admin_push_stats(pass) [anon, passcode-gated]. Full bodies as applied in migration "swk_web_push".
-- Cron (every minute, only fires when something is waiting):
-- select cron.schedule('swk-push','* * * * *', $$ select net.http_post(
--   url := 'https://<project>.supabase.co/functions/v1/swk-push',
--   headers := jsonb_build_object('Content-Type','application/json','x-cron-secret',(select value->>'secret' from public.swk_settings where key='push')),
--   body := '{}'::jsonb, timeout_milliseconds := 20000) where public.swk_push_pending(); $$);
