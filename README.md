# SWK Assistant

Chatbot for **SWK Solutions** (Sir Waqas Khan). Black, red and silver theme.

| File | What it is |
|---|---|
| `index.html` | The chatbot, shown full screen. Visitors pick an option, fill a short form, and the demo lecture unlocks. Follow-ups and Sir's replies appear in the same chat. |
| `admin.html` | **Sir's Desk**: inbox with replies, student list with CSV export, follow-up queue with WhatsApp buttons, reports, and setup for lectures and follow-up messages. |
| `sw.js`, `manifest.webmanifest`, `swk-icon-*.png`, `swk-badge.png` | Notifications and home-screen install (the service worker has to be its own file) |
| `swk-crest-silver.png` | Logo |
| `supabase/schema.sql` | Database: tables, functions and permissions (already applied to the SWK Supabase project) |

## How it works

1. A student picks an option, for example **O Level demo lecture**, and fills in the form.
2. **Notifications are required.** The lecture stays locked until the student taps Allow. If they blocked notifications, the chat shows how to turn them back on. Instagram/Facebook in-app browsers are asked to open the page in Chrome or Safari, and iPhone users to add SWK to their Home Screen; on those browsers only, a *Continue without notifications* button keeps them from getting stuck.
3. The lecture card unlocks. Tapping **Watch** copies the passcode and opens the Zoom clip.
4. Follow-ups are scheduled automatically (by default after 24h, 48h and 5 days). At the due time they arrive as a **push notification**, even if the page is closed, and they also wait in the student's chat. Their reply buttons save the answer, for example *Next week*, to the student's record.
5. Anything the chatbot can't answer goes to Sir's Desk. Sir replies from `admin.html`; the student gets a notification within a minute and sees the reply in their chat.
6. Students who haven't replied appear in **Follow-ups → Due now**, where Sir can send the follow-up on WhatsApp in one tap.

## Notifications

A Supabase cron job checks every minute and, only when something is waiting, calls the `swk-push` edge function, which sends the notifications. Push keys are stored in the locked settings table, not in this repo.

## Security

- Tables are locked (row-level security, no direct access).
- Students can only read their own chat, using a private token kept on their device.
- Everything in the admin panel needs Sir's passcode, which is stored hashed with bcrypt. You can change it in **Setup → Passcode**.

## Changing things

- **Demo lectures**: Sir's Desk → Setup → Lectures. You can add a separate lecture for each level and subject.
- **Follow-up messages and timing**: Sir's Desk → Setup → Follow-up messages.
- **Phone numbers, campuses, faculty, FAQ answers**: the `CAMPUSES`, `FACULTY` and `FAQ` lists near the top of the script in `index.html`.
