# SWK Assistant

Chatbot for **SWK Solutions** (Sir Waqas Khan). Black, red and silver theme.

| File | What it is |
|---|---|
| `index.html` | The chatbot, shown full screen. Visitors pick an option, fill a short form, and the demo lecture unlocks. Follow-ups and Sir's replies appear in the same chat. |
| `admin.html` | **Sir's Desk**: inbox with replies, student list with CSV export, follow-up queue with WhatsApp buttons, reports, and setup for lectures and follow-up messages. |
| `swk-crest-silver.png` | Logo |
| `supabase/schema.sql` | Database: tables, functions and permissions (already applied to the SWK Supabase project) |

## How it works

1. A student picks an option, for example **O Level demo lecture**, and fills in the form.
2. The lecture card unlocks straight away. Tapping **Watch** copies the passcode and opens the Zoom clip.
3. Follow-ups are scheduled automatically (by default after 24h, 48h and 5 days). They appear in the student's chat, with a chime and a notification, the next time they open it. Their reply buttons save the answer, for example *Next week*, to the student's record.
4. Anything the chatbot can't answer goes to Sir's Desk. Sir replies from `admin.html` and the reply shows up in the student's chat.
5. Students who haven't come back appear in **Follow-ups → Due now**, where Sir can send the follow-up on WhatsApp in one tap.

## Security

- Tables are locked (row-level security, no direct access).
- Students can only read their own chat, using a private token kept on their device.
- Everything in the admin panel needs Sir's passcode, which is stored hashed with bcrypt. You can change it in **Setup → Passcode**.

## Changing things

- **Demo lectures**: Sir's Desk → Setup → Lectures. You can add a separate lecture for each level and subject.
- **Follow-up messages and timing**: Sir's Desk → Setup → Follow-up messages.
- **Phone numbers, campuses, faculty, FAQ answers**: the `CAMPUSES`, `FACULTY` and `FAQ` lists near the top of the script in `index.html`.
