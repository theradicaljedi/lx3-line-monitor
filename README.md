# LX3 Line Monitor — web deploy (Supabase + Vercel)

This folder is a plain static site (`index.html`, no build step) that talks
directly to Supabase from the browser. It's the same dashboard that was
running as a Claude Artifact, converted to use Supabase instead of the
artifact's built-in database.

**Note on how this was produced:** the sandbox this was built in has no
`git`, `gh`, `vercel`, or `node`/`npm` installed, so the steps below are
things you run yourself (in your own terminal, or via the GitHub/Vercel
websites) — I couldn't execute them from here.

## 1. Set up Supabase

1. In your Supabase project, go to **SQL Editor → New query**, paste in the
   contents of `supabase_schema.sql` from this folder, and run it. This
   creates the one table the app uses (`units_data`) with public
   read/write policies (no login required — matches the access model you
   asked for).
2. Go to **Project Settings → API** and copy:
   - **Project URL**
   - **anon public** key (not the `service_role` key — never put that one
     in client-side code)
3. Open `index.html` in this folder and near the top of the last
   `<script>` block, replace:
   ```js
   const SUPABASE_URL = "YOUR_SUPABASE_PROJECT_URL";
   const SUPABASE_ANON_KEY = "YOUR_SUPABASE_ANON_PUBLIC_KEY";
   ```
   with your actual values. Both are meant to be public/client-visible —
   access is controlled by the RLS policies in `supabase_schema.sql`, not
   by keeping this key secret.

## 2. Push this folder to GitHub

From a terminal that has `git` installed, in this folder:

```bash
git init
git add .
git commit -m "LX3 Line Monitor — Supabase-backed web version"
```

Then create a new (can be private) GitHub repo — either on github.com
("New repository", don't initialize with a README) or with the `gh` CLI:

```bash
gh repo create lx3-line-monitor --private --source=. --remote=origin --push
```

If you created the repo on the website instead, connect and push manually:

```bash
git remote add origin https://github.com/<your-username>/lx3-line-monitor.git
git branch -M main
git push -u origin main
```

## 3. Import into Vercel

1. Go to [vercel.com/new](https://vercel.com/new), and import the GitHub
   repo you just pushed (Vercel will prompt you to authorize its GitHub
   App the first time — that's the one-time account link only you can do).
2. Framework preset: leave it as **Other** — this is a static site, no
   build command or output directory needed.
3. Click **Deploy**. Vercel gives you a `https://<project>.vercel.app`
   URL a few seconds later — that's the link anyone on your team can open.
4. Every future `git push` to `main` auto-redeploys.

## What's shared live vs. per-viewer

- **Shared, live, in Supabase** (via the `units_data` table + Realtime):
  the VQ checklist ticks, the Body/Paint/TCF-Out "Mark today" taps, and
  the issue log — exactly like the artifact version, but now backed by
  your own Supabase project instead of Claude's.
- **Per-browser only** (`localStorage`, not shared): which stages are
  checked in "Monitoring scope", and whether that panel is collapsed —
  same as before.
- **Baked into the page** (edit `index.html` and redeploy to update): the
  vehicle roster itself (`ROWS`), the 25-Sep PDF checklist seed data, and
  the VIN-to-color/stage mapping. If HNMPL sends a newer export, the
  `ROWS` array is what needs updating and re-pushing.

## Access model (as configured)

Anyone with the Vercel URL can read **and write** — there's no login. This
matches what you asked for ("anyone with the link, no login"), but it does
mean the link itself is the only thing gating access; treat it like you
would a shared internal spreadsheet link. If you later want to restrict
_writes_ to signed-in teammates only, that needs Supabase Auth added to the
app plus changing the RLS policies in `supabase_schema.sql` — ask if you
want that built.
