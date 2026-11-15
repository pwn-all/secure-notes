// Every word of the film lives here. To translate: copy to i18n/<code>.js, rename PROMO_I18N.en to PROMO_I18N.<code>,
// translate the values (missing keys fall back to English), check with index.html?lang=<code>, render with --lang <code>.
// `ui` holds strings of the real SecNote screens (website/langs/en.json); take them from the matching langs/<code>.json.
// Everything here is fictional: the company (Acme, acme.corp), people, passwords, note IDs. The app windows have no brand.
window.PROMO_I18N = window.PROMO_I18N || {};
PROMO_I18N.en = {
  // Comparison: values from the comparison table in the secure-notes README (no product names on screen).
  cmp: {
    intro: 'Sending someone a password?',
    intro_sub: 'Most people paste it into a chat. Some use a one-time secret app. Here is how SecNote compares.',
    title: 'How SecNote compares',
    sub: 'with typical open-source one-time secret apps',
    others: 'Typical alternatives',
    others_sub: 'open-source one-time secret apps',
    rows: [
      { label: 'The app is not tied to a server', key: 'Key difference', o: ['no', 'Needs its server or a build'], s: 'Plain HTML: keep your own copy', e: 'Check the page once, keep it, and use it with any SecNote server, even offline or in Tor Browser.' },
      { label: 'Gone after it is read', o: ['yes', 'Yes'], s: 'Yes, on the first read', e: 'Both delete the note once it is opened.' },
      { label: 'Encrypted in your browser', o: ['part', 'Most of them'], s: 'AES-256-GCM, key stays in the link', e: 'The server never sees the text or the key.' },
      { label: 'Never written to disk', o: ['no', 'Database or Redis'], s: 'RAM only', e: 'No disk, no database, no backup to leak.' },
      { label: 'A leaked note ID cannot burn it', o: ['no', 'No'], s: 'Reading needs a token from the key', e: 'Someone who sees a server log cannot destroy your note before it arrives.' },
      { label: 'Stops bots without a CAPTCHA', o: ['no', 'None, or a CAPTCHA'], s: 'Argon2id proof-of-work', e: 'Your browser solves a small memory-hard puzzle, so spam gets expensive.' },
      { label: 'Signed server replies', o: ['no', 'No'], s: 'Ed25519, checked by the page', e: 'A forged or replayed reply is rejected.' },
    ],
    summary: 'Deleting after reading is only the start. SecNote leaves nothing on the way to steal.',
    source: 'Based on the comparison table in the SecNote README.',
  },
  case_label: 'A real-life case',

  // The page works without the service that hosts it (README: "Offline / Tor Browser use").
  front_title: 'The app is not tied to the server',
  front_sub: 'SecNote is plain HTML and JavaScript. Keep a copy you trust and point it at any SecNote server.',
  front_url: 'file:///home/me/secnote/index.html',
  front_server: 'Server',
  front_hosts: ['notes.acme.corp', 'notes.instance', 'notes.example'],
  front_api: 'API calls only',
  front_nocode: 'No page code comes from the server',
  front_facts: ['No build step, no CDN', 'Works offline', 'Runs in Tor Browser', "Pin each server's signing key"],

  // AI agents: website/llms.txt, website/.well-known/*, index.md and the WebMCP tool in app.js (off unless the operator enables it).
  agent_title: 'Ready for AI agents',
  agent_sub: 'Agents find SecNote through standard discovery files and hand over a one-time link instead of the secret.',
  agent_head: 'AI agent',
  agent_ask: 'Create a staging DB user for Leo and send him the password.',
  agent_tool: 'create_encrypted_note',
  agent_tool_via: 'WebMCP',
  agent_done: 'Done. Leo gets a one-time link, not the password:',
  agent_disc: 'Discovery files',
  agent_files: [
    ['/llms.txt', 'Short guide for language models'],
    ['/.well-known/agent-skills/index.json', 'Agent skill: create and read notes'],
    ['/.well-known/api-catalog', 'API catalog (RFC 9727)'],
    ['/index.md', 'REST API described for agents'],
  ],
  agent_note: 'The WebMCP tool is switched on by the operator in app-config.js.',

  uses_title: 'More ways to use it',
  uses_sub: 'Anything that should be read once: logins, keys, codes, files.',
  uses: [
    { title: 'Onboarding', desc: 'IT sends a new hire the first login.', from: 'IT Support', addr: 'it@acme.corp', msg: 'Welcome, Sam! Your first login:' },
    { title: 'Partners and contractors', desc: 'Send a key outside the company. They need no account.', who: 'Partner (external)', msg: 'Staging API key:' },
    { title: 'Files', desc: 'Attach a document: it is encrypted with the note, when the admin enables files.', file: 'contract.pdf', size: '240 KB', msg: 'Signed contract' },
    { title: 'In person', desc: 'Show the link as a QR code. One scan, then it is gone.', msg: 'Scan to open once' },
  ],

  mode_without: 'Without SecNote',
  mode_with: 'With SecNote',
  later: '6 months later',
  rewind: 'Back to Mar 3',
  months: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],

  share_title: 'Every day, someone shares a password in a chat',
  share_sub: 'Team chat, messenger, e-mail, helpdesk. It is quick, and everyone does it.',
  kept: 'Kept in history',

  leak_title: 'Months later, one account leaks',
  leak_sub: 'Whoever gets the history gets every password ever shared in it.',
  leak_how: ['Phished login', 'Lost phone', 'Mailbox breach', 'Leaked backup'],
  search_head: 'Leaked history',
  search_src: '4 sources',
  search_q: 'password',
  exposed: 'Exposed',

  with_title: 'Same day. This time, with SecNote',
  with_sub: 'The password goes into SecNote. The chat only gets a one-time link.',
  burned: 'Read once · destroyed',

  leak2_title: 'Same leak. Nothing to steal',
  leak2_sub: 'The history keeps only dead links: each note was read once, unread ones expired within 24 hours.',

  admin_title: 'One admin installs it. Everyone is covered',
  admin_sub: 'On your own domain. It works in any messenger, mail or ticket system, because it is just a link.',
  admin_term: 'Terminal',
  admin_server: 'RAM only',
  admin_apps: ['Team chat', 'Messenger', 'E-mail', 'Helpdesk', 'Any other app'],
  admin_facts: ['Encrypted in the browser', 'Stored in RAM only, never on disk', 'No user accounts to manage', 'Free and open source'],

  outro_tag: 'Share it once. Leave nothing to leak.',
  outro_sub: 'For the whole company, or just one password to a friend.',
  outro_badges: ['e2ee', 'AES-256-GCM', 'burn after read', 'self-hosted'],
  outro_url: 'github.com/pwn-all/secure-notes',

  // The four apps (no brands): who asks, who answers, what the password is for.
  apps: [
    { kind: 'Team chat', head: '# dev-ops', side: ['Acme', '# general', '# dev-ops', '# releases'],
      ask_who: 'Leo', ask: 'Can someone send me the prod DB password?', who: 'Anna', label: 'prod DB password:', time: '10:41' },
    { kind: 'Messenger', head: 'Max', status: 'online',
      ask: 'What is the office Wi-Fi?', label: 'Office Wi-Fi password:', time: '10:42' },
    { kind: 'E-mail', head: 'Your VPN access', from: 'IT Support', addr: 'it@acme.corp', to: 'to sam@acme.corp',
      hi: 'Hi Sam,', label: 'your VPN password:', time: '10:43' },
    { kind: 'Helpdesk', head: '#4821 · Router reset', state: 'Resolved', who: 'Kim (IT)', label: 'Router admin password:', time: '10:44' },
  ],

  // Strings of the real SecNote screens (website/langs/en.json).
  ui: {
    online: 'online',
    hero_title: 'What secret do you want to share?',
    composer_ph: 'Write a secret…',
    hint: 'End-to-end encrypted · burns after reading',
    status_checking: 'Checking that you are not a robot…',
    status_human: 'You are not a robot',
    link_ready: 'Done. Here is your one-time link:',
    link_copy: 'Copy link',
    link_copied: 'Copied',
    link_qr: 'QR code',
    burned_title: 'This note is already gone.',
    burned_sub: 'It was read, burned or has expired. Each note opens only once.',
  },

  // Fake demo values.
  secrets: ['S3cr3t-Pa55w0rd', 'Gu3st!Acme26', 'Vq7#pL2xNm', 'R0ut3r-9kQ!'],
  ids: ['ii2Snl4V1KtAUDF17uGmCg', 'Qm8xR2vTnL0aWk5sYd3HbQ', 'b7KpZ4wYc1EoRt6uJf9GnA', 'Hs3NdU9qA6fLx2CvPe8KtW'],
  pin: 'R4cS0q7Wm2xPv9LhTn3GkZ8bYe1JdUa6fQo5iVt0wNc',
  key: 'oKqaIUk1peJufOSErBMOxvEPppkFWrVFuMVUrFR2yZ4',
  org_host: 'notes.acme.corp',
  org_mail: 'admin@acme.corp',
};
