function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

/* ===================================================
   AUTH SYSTEM
   =================================================== */
const AUTH_KEY   = 'ah_users_v1';
const SESS_KEY   = 'ah_session_v1';
const TOKEN_DURATION = 60 * 60 * 1000; // 1 hour in ms
const WARN_THRESHOLD = 5 * 60 * 1000;  // warn at 5 min remaining
const CRIT_THRESHOLD = 60 * 1000;       // critical at 1 min remaining
let currentUser  = null;   // { username, name, email }

function getUsers() { return loadWithIntegrity(AUTH_KEY) || []; }
function saveUsers(u) { saveWithIntegrity(AUTH_KEY, u); }
function getSession() { try { return JSON.parse(localStorage.getItem(SESS_KEY) || 'null'); } catch(e) { return null; } }
function saveSession(u) { localStorage.setItem(SESS_KEY, JSON.stringify(u)); }  // expiresAt is stored inside u
function clearSession() { localStorage.removeItem(SESS_KEY); }

function switchTab(tab) {
  ['login','register'].forEach(t => {
    document.getElementById('tab-' + t).classList.toggle('active', t === tab);
    document.getElementById('form-' + t).classList.toggle('hidden', t !== tab);
  });
  clearAuthMsgs();
}

function clearAuthMsgs() {
  ['login-err','login-ok','reg-err','reg-ok'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.className = el.className.replace(' show',''); el.textContent = ''; }
  });
  document.querySelectorAll('.field input').forEach(el => el.classList.remove('err'));
}

function showAuthMsg(id, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  if (!el.className.includes('show')) el.className += ' show';
}

function togglePw(inputId, btn) {
  const inp = document.getElementById(inputId);
  if (!inp) return;
  inp.type = inp.type === 'password' ? 'text' : 'password';
  btn.textContent = inp.type === 'password' ? '\u{1F441}' : '\u{1F648}';
}

function checkStrength(val) {
  const fill = document.getElementById('pw-fill');
  const label = document.getElementById('pw-label');
  if (!fill || !label) return;
  let score = 0;
  if (val.length >= 8) score++;
  if (/[A-Z]/.test(val)) score++;
  if (/[0-9]/.test(val)) score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;
  const configs = [
    {pct:'0%', color:'transparent', text:''},
    {pct:'25%', color:'#ef4444', text:'Weak'},
    {pct:'50%', color:'#f59e0b', text:'Fair'},
    {pct:'75%', color:'#3b82f6', text:'Good'},
    {pct:'100%', color:'#22c55e', text:'Strong'},
  ];
  const c = configs[score] || configs[0];
  fill.style.width = c.pct; fill.style.background = c.color;
  label.textContent = c.text; label.style.color = c.color;
}

function doRegister(e) {
  e.preventDefault(); clearAuthMsgs();
  const name     = document.getElementById('reg-name').value.trim();
  const username = document.getElementById('reg-username').value.trim();
  const email    = document.getElementById('reg-email').value.trim().toLowerCase();
  const pw       = document.getElementById('reg-pw').value;
  const pw2      = document.getElementById('reg-pw2').value;

  if (!name) { showAuthMsg('reg-err', '\u274C Full name is required.'); document.getElementById('reg-name').classList.add('err'); return; }
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) { showAuthMsg('reg-err', '\u274C Username must be 3-20 chars: letters, numbers, underscores only.'); document.getElementById('reg-username').classList.add('err'); return; }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { showAuthMsg('reg-err', '\u274C Please enter a valid email address.'); document.getElementById('reg-email').classList.add('err'); return; }
  if (pw.length < 8) { showAuthMsg('reg-err', '\u274C Password must be at least 8 characters.'); document.getElementById('reg-pw').classList.add('err'); return; }
  if (pw !== pw2) { showAuthMsg('reg-err', '\u274C Passwords do not match.'); document.getElementById('reg-pw2').classList.add('err'); return; }

  const users = getUsers();
  if (users.find(u => u.email === email)) { showAuthMsg('reg-err', '\u274C An account with that email already exists. Please sign in.'); document.getElementById('reg-email').classList.add('err'); return; }
  if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) { showAuthMsg('reg-err', '\u274C That username is already taken. Please choose another.'); document.getElementById('reg-username').classList.add('err'); return; }

  const user = { name, username, email, pwHash: simHash(pw), joinedAt: Date.now() };
  users.push(user); saveUsers(users);
  showAuthMsg('reg-ok', '\u2705 Account created! Signing you in\u2026');
  document.getElementById('reg-btn').disabled = true;
  setTimeout(() => loginUser(user), 900);
}

function doLogin(e) {
  e.preventDefault(); clearAuthMsgs();
  const email = document.getElementById('login-email').value.trim().toLowerCase();
  const pw    = document.getElementById('login-pw').value;
  if (!email) { showAuthMsg('login-err', '\u274C Email is required.'); document.getElementById('login-email').classList.add('err'); return; }
  if (!pw)    { showAuthMsg('login-err', '\u274C Password is required.'); document.getElementById('login-pw').classList.add('err'); return; }
  const users = getUsers();
  const user = users.find(u => u.email === email);
  if (!user || user.pwHash !== simHash(pw)) { showAuthMsg('login-err', '\u274C Incorrect email or password. Please try again.'); document.getElementById('login-pw').classList.add('err'); return; }
  showAuthMsg('login-ok', '\u2705 Welcome back, ' + user.name + '! Loading\u2026');
  document.getElementById('login-btn').disabled = true;
  setTimeout(() => loginUser(user), 700);
}

function loginUser(user) {
  currentUser = { name: user.name, username: user.username, email: user.email, expiresAt: Date.now() + TOKEN_DURATION };
  saveSession(currentUser);
  updateHeaderUser();
  hideAuthGate();
  startSessionTimer();
  toast('\u{1F44B} Welcome, ' + user.name + '! You are signed in as @' + user.username, 'success');
  pushAct(user.username + ' joined the auction');
}

function doLogout() {
  currentUser = null; clearSession();
  stopSessionTimer();
  updateHeaderUser();
  showAuthGate();
  toast('\u{1F44B} You have been signed out.', 'info');
}

function updateHeaderUser() {
  const w = document.getElementById('user-widget');
  const av = document.getElementById('user-avatar');
  const nm = document.getElementById('user-name-display');
  if (currentUser) {
    w.style.display = 'flex';
    av.textContent = currentUser.username.slice(0,2).toUpperCase();
    nm.textContent = '@' + currentUser.username;
  } else {
    w.style.display = 'none';
  }
}

function hideAuthGate() {
  const g = document.getElementById('auth-gate');
  g.classList.add('hidden');
  setTimeout(() => { g.style.display = 'none'; }, 320);
}

function showAuthGate() {
  const g = document.getElementById('auth-gate');
  g.style.display = 'flex';
  requestAnimationFrame(() => g.classList.remove('hidden'));
  clearAuthMsgs();
  document.getElementById('login-btn').disabled = false;
  document.getElementById('reg-btn').disabled = false;
}

/* Simple deterministic hash (NOT cryptographic — demo only) */
function simHash(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) { h = ((h << 5) + h) ^ str.charCodeAt(i); h = h >>> 0; }
  return h.toString(16);
}

/* ===================================================
   AUCTION DATA
   =================================================== */
const LOTS_DEF = [
  {id:'lot-001',lotNumber:'001',title:'Vintage Leica M3 Rangefinder Camera (1957)',category:'Photography',description:'A pristine 1957 Leica M3 double-stroke rangefinder camera in remarkable condition. Original leatherette intact, viewfinder clear with minimal dust. Shutter fires on all speeds including the coveted 1/1000s curtain. Includes original case and strap.',startingPrice:1200,increment:100,durationMins:18,emoji:'\u{1F4F7}',artColor:'linear-gradient(135deg,#1a1a2e,#16213e)'},
  {id:'lot-002',lotNumber:'002',title:'First Edition "Dune" by Frank Herbert (1965)',category:'Books & Manuscripts',description:'A true first printing of Frank Herbert\'s magnum opus Dune, published by Chilton Books in 1965. Minor shelf wear to dust jacket, text block clean and tight. Signature on title page attributed to Herbert with provenance documentation.',startingPrice:4000,increment:250,durationMins:35,emoji:'\u{1F4DA}',artColor:'linear-gradient(135deg,#2d1b69,#11998e)'},
  {id:'lot-003',lotNumber:'003',title:'Nike Air Jordan 1 "Bred" OG (1985, Deadstock)',category:'Sneakers',description:'Deadstock pair of the original 1985 Nike Air Jordan 1 "Bred" colorway. Never worn, original box with lid intact. Size US 10.5. The shoe that launched global sneaker culture. Yellowing on outsole consistent with age-appropriate oxidation.',startingPrice:8000,increment:500,durationMins:52,emoji:'\u{1F45F}',artColor:'linear-gradient(135deg,#c0392b,#1a1a1a)'},
  {id:'lot-004',lotNumber:'004',title:'Banksy "Balloon Girl" Canvas Print (Pest Control COA)',category:'Fine Art',description:'Authenticated Banksy "Balloon Girl" canvas print from a 2005 limited run, with Certificate of Authenticity from Pest Control, Banksy\'s official authentication body. Professionally framed. Condition: Excellent.',startingPrice:22000,increment:1000,durationMins:4,emoji:'\u{1F388}',artColor:'linear-gradient(135deg,#1f1f1f,#2d2d2d)'},
  {id:'lot-005',lotNumber:'005',title:'Rolex Submariner Date 16610 \u2014 Full Set (2001)',category:'Watches',description:'A 2001 Rolex Submariner Date reference 16610 in excellent condition. Full set: original box, papers dated June 2001, hang tags, and booklets. Dial in exceptional condition. A quintessential luxury sport watch.',startingPrice:9500,increment:500,durationMins:67,emoji:'\u{231A}',artColor:'linear-gradient(135deg,#0f3460,#533483)'},
  {id:'lot-006',lotNumber:'006',title:'Jimi Hendrix Signed Stratocaster (1968, JSA Authenticated)',category:'Music Memorabilia',description:'A 1968 Fender Stratocaster signed in blue ink by Jimi Hendrix, provenance traced to a backstage encounter at the Fillmore East. Includes framed authentication letter from JSA. The guitar remains playable with original pickups.',startingPrice:65000,increment:2500,durationMins:90,emoji:'\u{1F3B8}',artColor:'linear-gradient(135deg,#fc4a1a,#f7b733)'},
  {id:'lot-007',lotNumber:'007',title:'Apple-1 Computer Board (Wozniak-Signed Replica, #12/50)',category:'Technology',description:'A fully functional replica of the original 1976 Apple-1 computer board, hand-signed by Steve Wozniak at a Silicon Valley event in 2018. Signature authenticated with event photographs and COA. Numbered 12 of 50.',startingPrice:3500,increment:200,durationMins:28,emoji:'\u{1F4BB}',artColor:'linear-gradient(135deg,#11998e,#38ef7d)'},
  {id:'lot-008',lotNumber:'008',title:'Victorian Sterling Silver Tea Service (Birmingham, 1887)',category:'Antiques',description:'A complete 5-piece Victorian sterling silver tea service hallmarked Birmingham 1887: teapot, coffee pot, cream jug, sugar basin, and slop bowl. Maker\'s marks visible. Bright-cut engraving pristine. Approx. 1,450g troy.',startingPrice:2800,increment:150,durationMins:44,emoji:'\u2615',artColor:'linear-gradient(135deg,#c9d6df,#52616b)'},
  {id:'lot-009',lotNumber:'009',title:'NASA Apollo 11 Mission-Used Beta Cloth (1969)',category:'Space Memorabilia',description:'A piece of beta cloth from the Apollo 11 mission, presented in a custom acrylic display case with NASA lot number and provenance documentation. A tangible link to humanity\'s greatest adventure.',startingPrice:15000,increment:750,durationMins:8,emoji:'\u{1F680}',artColor:'linear-gradient(135deg,#0b0c10,#1f2833)'},
  {id:'lot-010',lotNumber:'010',title:'Pok\u00E9mon Charizard Holographic 1st Edition PSA 10',category:'Trading Cards',description:'The crown jewel of Pok\u00E9mon collecting \u2014 a 1999 Base Set Charizard Holographic 1st Edition graded PSA 10 Gem Mint. Fewer than 3,000 in this grade. The single most iconic trading card in modern culture.',startingPrice:18000,increment:1000,durationMins:77,emoji:'\u{1F409}',artColor:'linear-gradient(135deg,#f7971e,#ffd200)'},
  {id:'lot-011',lotNumber:'011',title:'Hand-Painted Murano Sommerso Glass Vase (c.1958)',category:'Fine Art',description:'An extraordinary mid-century Murano sommerso glass vase with hand-applied aventurine inclusions. Attributed to Venini manufactory circa 1958. Standing 38cm with amethyst-to-clear gradient. No chips, cracks, or repairs.',startingPrice:1800,increment:100,durationMins:55,emoji:'\u{1F3FA}',artColor:'linear-gradient(135deg,#667eea,#764ba2)'},
  {id:'lot-012',lotNumber:'012',title:'Muhammad Ali Signed Everlast Boxing Gloves (c.1975)',category:'Sports Memorabilia',description:'A pair of Everlast boxing gloves signed by Muhammad Ali circa 1975 with bold black marker signatures on both gloves. JSA hologram and Letter of Authenticity included. Displayed on an original oak plaque.',startingPrice:5500,increment:250,durationMins:2,emoji:'\u{1F94A}',artColor:'linear-gradient(135deg,#c94b4b,#4b134f)'},
];

const SIM_BIDDERS = ['Collector_88','Anonymous','BidderX','VintagePro','LotHunter','ArtDealer99','SnipeMaster','Reserved_Buyer','GoldBidder','SilentBid','AuctionPro7','LuxurySeeker','RareFinds','PlatinumBid','Connoisseur'];
const URGENT_MS  = 5 * 60 * 1000;

function calcStateHash(data) {
  let str = JSON.stringify(data);
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return (hash >>> 0).toString(16);
}

function saveWithIntegrity(key, data) {
  const payload = {
    data: data,
    sig: calcStateHash(data),
    ts: Date.now()
  };
  localStorage.setItem(key, JSON.stringify(payload));
}

function loadWithIntegrity(key) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || !parsed.data || !parsed.sig) return null;
    if (calcStateHash(parsed.data) !== parsed.sig) {
      console.warn('Tamper detected on storage key:', key);
      toast('⚠️ Local data tamper detected! Resetting state for security.', 'error');
      localStorage.removeItem(key);
      return null;
    }
    return parsed.data;
  } catch(e) {
    return null;
  }
}

const STORAGE_KEY = 'auctionhouse_v1';

let lots = [], activeLotId = null;

function myBidder() { return currentUser ? currentUser.username : 'You'; }

/* ===== PERSISTENCE ===== */
function save() {
  saveWithIntegrity(STORAGE_KEY, lots.map(l => ({id:l.id,currentBid:l.currentBid,bidHistory:l.bidHistory,endsAt:l.endsAt,status:l.status})));
}
function load() { return loadWithIntegrity(STORAGE_KEY); }

function initLots() {
  const saved = load(), now = Date.now();
  lots = LOTS_DEF.map(def => {
    const s = saved ? saved.find(x => x.id === def.id) : null;
    const endsAt = s ? s.endsAt : now + def.durationMins * 60000;
    return { ...def, currentBid: s ? s.currentBid : def.startingPrice, bidHistory: s ? s.bidHistory : [], endsAt, status: now >= endsAt ? 'closed' : (s ? s.status : 'open') };
  });
}

/* ===== HELPERS ===== */
function fmt(n) { return '$' + Number(n).toLocaleString('en-US', {minimumFractionDigits:0,maximumFractionDigits:0}); }
function getInc(lot) { const b = lot.currentBid; if (b<500) return 25; if (b<2000) return 100; if (b<10000) return 250; if (b<50000) return 1000; return 2500; }
function minBid(lot) { return lot.currentBid + getInc(lot); }
function tLeft(lot) { return Math.max(0, lot.endsAt - Date.now()); }
function fmtCd(ms) {
  if (ms <= 0) return 'Closed';
  const s = Math.floor(ms/1000), d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60), sec = s%60;
  if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
  if (h > 0) return h + 'h ' + m + 'm ' + String(sec).padStart(2,'0') + 's';
  return m + ':' + String(sec).padStart(2,'0');
}
function relTime(ts) {
  const s = Math.floor((Date.now()-ts)/1000);
  if (s<5) return 'just now'; if (s<60) return s+'s ago';
  const m = Math.floor(s/60); if (m<60) return m+'m ago';
  const h = Math.floor(m/60); if (h<24) return h+'h ago';
  return Math.floor(h/24)+'d ago';
}
function byId(id) { return lots.find(l => l.id === id); }
function isMine(lot) { return lot.bidHistory.length > 0 && lot.bidHistory[0].bidder === myBidder(); }
function randSim() { return SIM_BIDDERS[Math.floor(Math.random() * SIM_BIDDERS.length)]; }
function ini(n) { return n.slice(0,2).toUpperCase(); }

/* ===== CATEGORIES ===== */
function buildCats() {
  const cats = [...new Set(lots.map(l => l.category))].sort();
  const sel = document.getElementById('cat-filter');
  cats.forEach(c => { const o = document.createElement('option'); o.value = c; o.textContent = c; sel.appendChild(o); });
}

/* ===== FILTER ===== */
function getFiltered() {
  const q = document.getElementById('search-input').value.trim().toLowerCase();
  const cat = document.getElementById('cat-filter').value;
  return lots.filter(l => (!q || l.title.toLowerCase().includes(q) || l.category.toLowerCase().includes(q)) && (!cat || l.category === cat));
}

/* ===== TICKER ===== */
const acts = [];
function pushAct(txt) { acts.push(txt); if (acts.length > 20) acts.shift(); rebuildTicker(); }
function rebuildTicker() {
  const el = document.getElementById('activity-inner'); if (!el) return;
  const items = acts.map(e => '<span class="ev"><span class="dot"></span>' + e + '</span>').join('');
  el.innerHTML = items + items;
}

/* ===== CLOCK ===== */
function updateClock() { const el = document.getElementById('wall-clock'); if (el) el.textContent = new Date().toLocaleTimeString(); }

/* ===== CATALOG ===== */
function renderCatalog() {
  const cat = document.getElementById('catalog');
  const f = getFiltered(), open = f.filter(l => l.status==='open'), closed = f.filter(l => l.status==='closed');
  const oc = lots.filter(l => l.status==='open').length;
  document.getElementById('open-count-hdr').textContent = oc + ' item' + (oc!==1?'s':'') + ' active';
  document.getElementById('lot-count-label').textContent = f.length + ' item' + (f.length!==1?'s':'') + ' shown';
  cat.innerHTML = '';
  if (f.length === 0) { cat.innerHTML = '<div class="empty-state"><div class="empty-icon">&#x1F50D;</div><h3>No items match your search</h3><p>Try a different keyword or clear the filter.</p></div>'; return; }
  if (open.length > 0) { cat.appendChild(secHdr('Live Items', open.length)); open.forEach(l => cat.appendChild(buildCard(l))); }
  if (closed.length > 0) { cat.appendChild(secHdr('Closed Items', closed.length)); closed.forEach(l => cat.appendChild(buildCard(l))); }
}

function secHdr(title, count) {
  const d = document.createElement('div'); d.className = 'catalog-section-header';
  d.innerHTML = '<h2>' + title + '</h2><div class="divider"></div><span class="count-pill">' + count + '</span>';
  return d;
}

function buildCard(lot) {
  const ms = tLeft(lot), urgent = lot.status==='open' && ms<URGENT_MS, mine = isMine(lot);
  const card = document.createElement('div');
  card.className = 'lot-card' + (lot.status==='closed'?' closed':'') + (urgent?' closing-soon':'') + (mine&&lot.status==='open'?' my-bid':'');
  card.setAttribute('role','listitem'); card.setAttribute('tabindex','0'); card.dataset.id = lot.id;
  let badge = '';
  if (mine && lot.status==='open') badge = '<span class="my-bid-badge">&#x2191; My Bid</span>';
  else if (lot.status==='closed') badge = '<span class="status-badge closed">Closed</span>';
  else if (urgent) badge = '<span class="status-badge closing">Ending Soon</span>';
  else badge = '<span class="status-badge open">Open</span>';
  const cdCls = lot.status==='closed'?'ended':(urgent?'urgent':'');
  const cdTxt = lot.status==='closed'?'Closed':fmtCd(ms);
  const icon = lot.status==='open'?'&#x23F1;':'&#x1F512;';
  card.innerHTML = '<div class="lot-thumb"><div class="lot-art" style="background:'+lot.artColor+'"><span class="art-emoji">'+lot.emoji+'</span><span class="art-label">Item #'+lot.lotNumber+'</span></div><div class="lot-num-badge">ITEM #'+lot.lotNumber+'</div>'+badge+'</div>'+
    '<div class="lot-body"><div class="lot-category">'+lot.category+'</div><div class="lot-title">'+lot.title+'</div>'+
    '<div class="lot-bid-row"><div class="lot-current-bid"><span class="bid-label">'+(lot.status==='closed'?'Final Bid':'Current Bid')+'</span><span class="bid-amount" id="cb-'+lot.id+'">'+fmt(lot.currentBid)+'</span></div>'+
    '<div class="bid-count" id="bc-'+lot.id+'">'+lot.bidHistory.length+' bid'+(lot.bidHistory.length!==1?'s':'')+'</div></div>'+
    '<div class="lot-countdown '+cdCls+'" id="cd-'+lot.id+'">'+icon+' '+cdTxt+'</div></div>';
  card.addEventListener('click', () => openModal(lot.id));
  card.addEventListener('keydown', e => { if (e.key==='Enter'||e.key===' ') { e.preventDefault(); openModal(lot.id); } });
  return card;
}

/* ===== TICK ===== */
function updateCards() {
  lots.forEach(lot => {
    const ms = tLeft(lot), urgent = lot.status==='open' && ms<URGENT_MS;
    const cdEl = document.getElementById('cd-'+lot.id);
    if (cdEl) { cdEl.className='lot-countdown '+(lot.status==='closed'?'ended':(urgent?'urgent':'')); cdEl.innerHTML=(lot.status==='open'?'&#x23F1;':'&#x1F512;')+' '+(lot.status==='closed'?'Closed':fmtCd(ms)); }
    const bEl = document.getElementById('cb-'+lot.id); if (bEl) bEl.textContent = fmt(lot.currentBid);
    const bcEl = document.getElementById('bc-'+lot.id); if (bcEl) bcEl.textContent = lot.bidHistory.length+' bid'+(lot.bidHistory.length!==1?'s':'');
    if (lot.status==='open' && ms<=0) {
      lot.status='closed'; save();
      const c = document.querySelector('.lot-card[data-id="'+lot.id+'"]');
      if (c) { c.classList.add('closed'); c.classList.remove('closing-soon','my-bid'); }
      toast('\u{1F512} Item #'+lot.lotNumber+' closed! Final: '+fmt(lot.currentBid), 'info');
      pushAct('Item #'+lot.lotNumber+' closed \u2014 Final: '+fmt(lot.currentBid));
      if (activeLotId===lot.id) renderBody();
    }
    const c = document.querySelector('.lot-card[data-id="'+lot.id+'"]');
    if (c && lot.status==='open') c.classList.toggle('closing-soon', urgent);
  });
  if (activeLotId) {
    const lot = byId(activeLotId);
    if (lot) {
      const ms2=tLeft(lot), urg=lot.status==='open'&&ms2<URGENT_MS;
      const v=document.getElementById('mcd-val'); if (v) v.textContent=lot.status==='closed'?'Closed':fmtCd(ms2);
      const b=document.getElementById('mcd-box'); if (b) b.className='modal-countdown '+(lot.status==='closed'?'ended':(urg?'urgent':''));
      const mb=document.getElementById('m-bid'); if (mb) mb.textContent=fmt(lot.currentBid);
      const mm=document.getElementById('m-min'); if (mm) mm.textContent=lot.status==='closed'?fmt(lot.currentBid):fmt(minBid(lot));
    }
  }
  document.querySelectorAll('.bid-time[data-ts]').forEach(el => { el.textContent = relTime(+el.dataset.ts); });
}

/* ===== MODAL ===== */
function openModal(id) {
  activeLotId = id;
  const lot = byId(id); if (!lot) return;
  document.getElementById('modal-lot-num').textContent = 'Item #'+lot.lotNumber;
  document.getElementById('modal-category').textContent = lot.category;
  document.getElementById('modal-title-el').textContent = lot.title;
  document.getElementById('modal-thumb').innerHTML = '<div class="lot-art" style="background:'+lot.artColor+'"><span class="art-emoji">'+lot.emoji+'</span></div>';
  renderBody();
  document.getElementById('modal-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
  setTimeout(() => document.getElementById('modal-close').focus(), 50);
}
function closeModal() {
  activeLotId = null;
  document.getElementById('modal-overlay').classList.remove('open');
  document.body.style.overflow = '';
}

function renderBody() {
  const lot = byId(activeLotId); if (!lot) return;
  const body = document.getElementById('modal-body');
  const ms=tLeft(lot), urg=lot.status==='open'&&ms<URGENT_MS, mine=isMine(lot);
  body.innerHTML =
    '<div class="modal-section"><div class="section-title">Auction Stats</div><div class="stats-row">'+
      '<div class="stat-box highlight"><span class="stat-label">'+(lot.status==='closed'?'Final Bid':'Current Bid')+'</span><span class="stat-value" id="m-bid">'+fmt(lot.currentBid)+'</span><span class="stat-sub">'+lot.bidHistory.length+' bid'+(lot.bidHistory.length!==1?'s':'')+' placed</span></div>'+
      '<div class="stat-box"><span class="stat-label">Starting Price</span><span class="stat-value neutral">'+fmt(lot.startingPrice)+'</span><span class="stat-sub">Reserve price</span></div>'+
      '<div class="stat-box"><span class="stat-label">'+(lot.status==='closed'?'Winner':'Min. Next Bid')+'</span><span class="stat-value neutral" id="m-min">'+(lot.status==='closed'?fmt(lot.currentBid):fmt(minBid(lot)))+'</span><span class="stat-sub">'+(lot.status==='closed'?(lot.bidHistory[0]?lot.bidHistory[0].bidder:'No bids'):'Increment: '+fmt(getInc(lot)))+'</span></div>'+
      '<div class="modal-countdown '+(lot.status==='closed'?'ended':(urg?'urgent':''))+'" id="mcd-box"><span class="stat-label">Time Remaining</span><span id="mcd-val">'+(lot.status==='closed'?'Closed':fmtCd(ms))+'</span></div>'+
    '</div></div>'+
    '<div class="modal-section"><div class="section-title">Description</div><p class="desc-text">'+lot.description+'</p></div>'+
    '<div class="modal-section"><div class="section-title">Place a Bid</div>'+(lot.status==='closed'?closedNotice(lot):bidSection(lot,mine))+'</div>'+
    '<div class="modal-section"><div class="section-title">Bid History ('+lot.bidHistory.length+')</div>'+bidHist(lot)+'</div>';

  if (lot.status==='open' && currentUser) {
    const f = document.getElementById('bid-form');
    if (f) f.addEventListener('submit', e => submitBid(e, lot.id));
    const inp = document.getElementById('bid-input');
    if (inp) inp.addEventListener('input', () => { inp.classList.remove('error'); hideBidMsg(); });
  }
  if (lot.status==='open' && !currentUser) {
    const btn = document.getElementById('open-login-btn');
    if (btn) btn.addEventListener('click', () => { closeModal(); showAuthGate(); });
  }
}

function closedNotice(lot) {
  const w = lot.bidHistory[0];
  const isMe = w && w.bidder === myBidder();
  return '<div class="closed-notice"><div class="winner">&#x1F3C6; '+(w?(isMe?'&#x1F389; You won with '+fmt(w.amount)+'!':w.bidder+' won with '+fmt(w.amount)):'No bids \u2014 item passed')+'</div><div>This item is closed. No further bids accepted.</div></div>';
}

function bidSection(lot, mine) {
  if (!currentUser) {
    return '<div class="login-to-bid">'+
      '<p>&#x1F511; You must be signed in to place a bid on this item.</p>'+
      '<button class="login-prompt-btn" id="open-login-btn">Sign In to Bid &rarr;</button>'+
    '</div>';
  }
  const min = minBid(lot);
  return '<div class="bid-form">'+
    (mine?'<div class="bid-msg info" style="display:flex">&#x2B50; You (@'+escapeHtml(currentUser.username)+') hold the highest bid of '+fmt(lot.currentBid)+'. Raise to increase your lead.</div>':'')+
    '<div id="bid-msg" class="bid-msg" role="alert"></div>'+
    '<form id="bid-form" novalidate><div class="bid-form-row"><div class="bid-input-wrap"><label class="bid-input-label" for="bid-input">Your Bid Amount</label><div class="bid-input-inner"><span class="bid-currency">$</span>'+
    '<input type="number" id="bid-input" class="bid-number-input" min="'+min+'" step="'+getInc(lot)+'" value="'+min+'" aria-label="Bid amount" autocomplete="off" /></div></div>'+
    '<button type="submit" class="bid-submit-btn">Place Bid &#x2192;</button></div>'+
    '<div class="bid-hint">Minimum: <strong>'+fmt(min)+'</strong> &middot; Increment: <strong>'+fmt(getInc(lot))+'</strong> &middot; Bidding as: <strong>@'+currentUser.username+'</strong></div>'+
    '</form></div>';
}

function bidHist(lot) {
  if (!lot.bidHistory.length) return '<div class="bid-history-empty">No bids yet \u2014 be the first!</div>';
  return '<div class="bid-history">'+lot.bidHistory.map((b,i) => {
    const isMe = b.bidder === myBidder();
    return '<div class="bid-item'+(isMe?' mine':'')+'">'+
      '<div class="bid-avatar '+(isMe?'you':'bot')+'">'+ini(b.bidder)+'</div>'+
      '<div class="bid-bidder">'+(isMe?'<span class="you-tag">@'+escapeHtml(b.bidder)+'</span>':'@'+escapeHtml(b.bidder))+(i===0?' &#x1F451;':'')+'</div>'+
      '<div class="bid-history-amount">'+fmt(b.amount)+'</div>'+
      '<div class="bid-time" data-ts="'+b.timestamp+'">'+relTime(b.timestamp)+'</div></div>';
  }).join('')+'</div>';
}

function showBidMsg(type, txt) { const el=document.getElementById('bid-msg'); if(!el) return; el.className='bid-msg '+type; el.style.display='flex'; el.textContent=txt; }
function hideBidMsg() { const el=document.getElementById('bid-msg'); if(el){el.style.display='none';el.textContent='';} }

/* ===== BID LOGIC ===== */
function submitBid(e, lotId) {
  e.preventDefault();
  if (!currentUser) { closeModal(); showAuthGate(); return; }
  const lot = byId(lotId); if (!lot) return;
  if (lot.status==='closed') { showBidMsg('error','\u{1F512} This item has already closed.'); return; }
  const inp = document.getElementById('bid-input');
  const amount = Math.floor(parseFloat(inp.value)), min = minBid(lot);
  if (isNaN(amount) || !Number.isFinite(amount) || amount < min || amount > 1000000000) { inp.classList.add('error'); showBidMsg('error','\u274C Bid must be at least '+fmt(min)+' (current: '+fmt(lot.currentBid)+' + increment: '+fmt(getInc(lot))+')'); return; }
  lot.bidHistory.unshift({bidder:myBidder(), amount, timestamp:Date.now()});
  lot.currentBid = amount; save();
  toast('\u2705 Your bid of '+fmt(amount)+' on Item #'+lot.lotNumber+' accepted!', 'success');
  pushAct('@'+currentUser.username+' bid '+fmt(amount)+' on Item #'+lot.lotNumber);
  renderBody();
  showBidMsg('success','\u2705 Bid of '+fmt(amount)+' placed! You are the highest bidder as @'+currentUser.username+'.');
  const cb=document.getElementById('cb-'+lot.id); if(cb) cb.textContent=fmt(lot.currentBid);
  const bc=document.getElementById('bc-'+lot.id); if(bc) bc.textContent=lot.bidHistory.length+' bid'+(lot.bidHistory.length!==1?'s':'');
  const c=document.querySelector('.lot-card[data-id="'+lot.id+'"]'); if(c) c.classList.add('my-bid');
}

/* ===== SIM BIDS ===== */
function simBids() {
  function go() {
    const open = lots.filter(l=>l.status==='open'&&tLeft(l)>30000);
    if (open.length) {
      const lot=open[Math.floor(Math.random()*open.length)], bidder=randSim(), amount=minBid(lot);
      lot.bidHistory.unshift({bidder,amount,timestamp:Date.now()});
      lot.currentBid=amount; save();
      const cb=document.getElementById('cb-'+lot.id); if(cb) cb.textContent=fmt(lot.currentBid);
      const bc=document.getElementById('bc-'+lot.id); if(bc) bc.textContent=lot.bidHistory.length+' bid'+(lot.bidHistory.length!==1?'s':'');
      pushAct('@'+bidder+' bid '+fmt(amount)+' on Item #'+lot.lotNumber);
      toast('\u{1F916} @'+bidder+' bid '+fmt(amount)+' on Item #'+lot.lotNumber, 'info');
      if (activeLotId===lot.id) { renderBody(); if(currentUser) showBidMsg('info','\u26A1 @'+bidder+' outbid you! Min: '+fmt(minBid(lot))); }
    }
    setTimeout(go, 12000+Math.random()*18000);
  }
  setTimeout(go, 8000+Math.random()*10000);
}

/* ===== TOAST ===== */
function toast(msg, type) {
  const c=document.getElementById('toast-container');
  const t=document.createElement('div'); t.className='toast '+(type||'info'); t.textContent=msg;
  c.appendChild(t); setTimeout(()=>{ if(t.parentNode) t.parentNode.removeChild(t); },3200);
}

/* ===== BOOT ===== */
function boot() {
  initLots(); buildCats(); renderCatalog();
  ['Auction now LIVE \u2014 12 items open for bidding',
   'Item #003 \u2014 Nike Air Jordan 1 attracted a new bid',
   'Item #004 \u2014 Banksy print closing in under 5 minutes!',
   'Item #009 \u2014 Apollo 11 cloth ending soon',
   'Item #012 \u2014 Ali gloves ending in 2 minutes!',
   'Create an account to start bidding on live items'].forEach(pushAct);
  simBids();
  setInterval(()=>{ updateClock(); updateCards(); }, 1000);

  document.getElementById('search-input').addEventListener('input', renderCatalog);
  document.getElementById('cat-filter').addEventListener('change', renderCatalog);
  document.getElementById('grid-view-btn').addEventListener('click', ()=>{ document.getElementById('catalog').classList.remove('list-view'); document.getElementById('grid-view-btn').classList.add('active'); document.getElementById('list-view-btn').classList.remove('active'); });
  document.getElementById('list-view-btn').addEventListener('click', ()=>{ document.getElementById('catalog').classList.add('list-view'); document.getElementById('list-view-btn').classList.add('active'); document.getElementById('grid-view-btn').classList.remove('active'); });
  document.getElementById('modal-close').addEventListener('click', closeModal);
  document.getElementById('modal-overlay').addEventListener('click', e=>{ if(e.target.id==='modal-overlay') closeModal(); });
  document.addEventListener('keydown', e=>{ if(e.key==='Escape'&&activeLotId) closeModal(); });

  /* check existing session — resume countdown from saved expiresAt */
  const sess = getSession();
  if (sess) {
    if (sess.expiresAt && Date.now() < sess.expiresAt) {
      // Valid session: keep the original expiresAt so timer continues from where it left off
      currentUser = sess;
      updateHeaderUser();
      hideAuthGate();
      startSessionTimer();
    } else {
      clearSession();
      // session was expired — show login gate (no popup on initial load)
    }
  }
}


/* ===================================================
   SESSION TOKEN MANAGEMENT
   =================================================== */
let sessionCheckInterval = null;

function startSessionTimer() {
  if (sessionCheckInterval) clearInterval(sessionCheckInterval);
  sessionCheckInterval = setInterval(checkSessionExpiry, 1000);
}

function stopSessionTimer() {
  if (sessionCheckInterval) { clearInterval(sessionCheckInterval); sessionCheckInterval = null; }
}

function checkSessionExpiry() {
  if (!currentUser || !currentUser.expiresAt) return;
  const remaining = currentUser.expiresAt - Date.now();

  // Update countdown display
  const timerEl = document.getElementById('session-time-val');
  const timerBox = document.getElementById('session-timer');
  if (timerEl && timerBox) {
    if (remaining <= 0) {
      timerEl.textContent = '0:00';
    } else {
      const totalSec = Math.floor(remaining / 1000);
      const h = Math.floor(totalSec / 3600);
      const m = Math.floor((totalSec % 3600) / 60);
      const s = totalSec % 60;
      timerEl.textContent = (h > 0 ? h + ':' : '') +
        String(m).padStart(h > 0 ? 2 : 1, '0') + ':' +
        String(s).padStart(2, '0');
    }

    // Style urgency
    timerBox.classList.remove('warning', 'critical');
    if (remaining <= CRIT_THRESHOLD) {
      timerBox.classList.add('critical');
    } else if (remaining <= WARN_THRESHOLD) {
      timerBox.classList.add('warning');
      // Show warning toast once at 5-min mark (only when first crossing threshold)
      if (!timerBox.dataset.warned) {
        timerBox.dataset.warned = '1';
        toast('\u26A0\uFE0F Session expires in 5 minutes. Save your bids!', 'error');
      }
    }
  }

  // Auto-logout on expiry
  if (remaining <= 0) {
    stopSessionTimer();
    forceLogout();
  }
}

function forceLogout() {
  currentUser = null;
  clearSession();
  updateHeaderUser();
  stopSessionTimer();
  // Close any open detail modal
  closeModal();
  // Show the expired overlay (not the auth gate)
  document.getElementById('expired-overlay').classList.add('show');
  toast('\u{1F512} Your session has expired. Please sign in again.', 'error');
}

function dismissExpired() {
  document.getElementById('expired-overlay').classList.remove('show');
  showAuthGate();
}

document.addEventListener('DOMContentLoaded', boot);