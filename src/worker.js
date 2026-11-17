const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers }
});
const text = (value, max = 5000) => String(value ?? '').trim().slice(0, max);
const id = () => crypto.randomUUID();
const encoder = new TextEncoder();
const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const fromB64 = (value) => Uint8Array.from(atob(value), c => c.charCodeAt(0));
async function sha256(value) {
  return b64(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
}
async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: encoder.encode(salt), iterations: 210000, hash: 'SHA-256' }, key, 256);
  return b64(bits);
}
function cookie(name, value, maxAge) {
  return `${name}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}
function clearCookie(name) { return `${name}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`; }
async function body(req) { try { return await req.json(); } catch { return {}; } }
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
async function currentUser(request, env) {
  const name = env.COOKIE_NAME || 'cps_session';
  const raw = request.headers.get('Cookie') || '';
  const match = raw.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  if (!match) return null;
  const tokenHash = await sha256(match[1]);
  const row = await env.DB.prepare(`SELECT u.id,u.name,u.email,u.role,u.status,u.class_id,c.name AS class_name
    FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN classes c ON c.id=u.class_id
    WHERE s.token_hash=? AND s.expires_at > datetime('now') AND u.status='active'`).bind(tokenHash).first();
  return row || null;
}
function requireRole(user, roles) { return !!user && roles.includes(user.role); }
async function handleApi(request, env) {
  const url = new URL(request.url); const path = url.pathname; const method = request.method;
  const cookieName = env.COOKIE_NAME || 'cps_session';
  const user = await currentUser(request, env);

  if (path === '/api/health' && method === 'GET') return json({ ok: true, app: env.APP_NAME || 'CPS Digital Diary' });

  if (path === '/api/classes' && method === 'GET') {
    const rows = await env.DB.prepare('SELECT id,name FROM classes WHERE active=1 ORDER BY name').all();
    return json({ classes: rows.results || [] });
  }

  if (path === '/api/auth/signup' && method === 'POST') {
    const data = await body(request);
    const name = text(data.name, 80); const email = text(data.email, 160).toLowerCase();
    const password = String(data.password || ''); const role = data.role === 'teacher' ? 'teacher' : 'student';
    const classId = text(data.classId, 64);
    if (name.length < 2 || !validEmail(email) || password.length < 8) return json({ error: 'Enter your name, a valid email and a password of at least 8 characters.' }, 400);
    const existing = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
    if (existing) return json({ error: 'An account with this email already exists.' }, 409);
    if (role === 'student') {
      const cls = await env.DB.prepare('SELECT id FROM classes WHERE id=? AND active=1').bind(classId).first();
      if (!cls) return json({ error: 'Please select a valid class.' }, 400);
    }
    let status = 'active';
    if (role === 'teacher') {
      status = 'pending';
      const code = text(data.teacherCode, 100);
      if (code) {
        const codeHash = await sha256(code);
        const valid = await env.DB.prepare(`SELECT id,uses_left FROM teacher_codes WHERE code_hash=? AND active=1 AND uses_left>0 AND (expires_at IS NULL OR expires_at>datetime('now'))`).bind(codeHash).first();
        if (valid) {
          status = 'active';
          await env.DB.prepare('UPDATE teacher_codes SET uses_left=uses_left-1 WHERE id=?').bind(valid.id).run();
        }
      }
    }
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await passwordHash(password, salt); const userId = id();
    await env.DB.prepare('INSERT INTO users(id,name,email,password_hash,password_salt,role,status,class_id) VALUES(?,?,?,?,?,?,?,?)')
      .bind(userId, name, email, hash, salt, role, status, role === 'student' ? classId : null).run();
    if (status === 'pending') return json({ ok: true, pending: true, message: 'Teacher account submitted. An admin must approve it.' }, 201);
    return createSession(userId, env, cookieName);
  }

  if (path === '/api/auth/login' && method === 'POST') {
    const data = await body(request); const email = text(data.email, 160).toLowerCase(); const password = String(data.password || '');
    const account = await env.DB.prepare('SELECT id,password_hash,password_salt,status FROM users WHERE email=?').bind(email).first();
    if (!account || await passwordHash(password, account.password_salt) !== account.password_hash) return json({ error: 'Incorrect email or password.' }, 401);
    if (account.status === 'pending') return json({ error: 'Your teacher account is awaiting admin approval.' }, 403);
    if (account.status !== 'active') return json({ error: 'This account is disabled. Contact the school admin.' }, 403);
    return createSession(account.id, env, cookieName);
  }

  if (path === '/api/auth/logout' && method === 'POST') {
    const raw = request.headers.get('Cookie') || ''; const match = raw.match(new RegExp(`(?:^|;\\s*)${cookieName}=([^;]+)`));
    if (match) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(match[1])).run();
    return json({ ok: true }, 200, { 'set-cookie': clearCookie(cookieName) });
  }

  if (path === '/api/auth/me' && method === 'GET') return json({ user });

  if (path === '/api/admin/bootstrap' && method === 'POST') {
    const data = await body(request);
    if (!env.BOOTSTRAP_SECRET || request.headers.get('x-bootstrap-secret') !== env.BOOTSTRAP_SECRET) return json({ error: 'Not authorized.' }, 403);
    const email = text(data.email, 160).toLowerCase(); const name = text(data.name || 'CPS Admin', 80); const password = String(data.password || '');
    if (!validEmail(email) || password.length < 12) return json({ error: 'Provide a valid email and an admin password of at least 12 characters.' }, 400);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin'").first();
    if (count.n > 0) return json({ error: 'Admin already exists. Bootstrap is locked.' }, 409);
    const salt = b64(crypto.getRandomValues(new Uint8Array(16))); const hash = await passwordHash(password, salt);
    await env.DB.prepare("INSERT INTO users(id,name,email,password_hash,password_salt,role,status) VALUES(?,?,?,?,?,'admin','active')").bind(id(), name, email, hash, salt).run();
    return json({ ok: true, message: 'Admin account created. Sign in normally.' }, 201);
  }

  if (path.startsWith('/api/') && !user && !['/api/auth/signup','/api/auth/login','/api/auth/me','/api/classes','/api/health','/api/admin/bootstrap'].includes(path)) return json({ error: 'Authentication required.' }, 401);

  if (path === '/api/diary' && method === 'GET') {
    const requestedClass = text(url.searchParams.get('classId'), 64);
    const classId = user.role === 'student' ? user.class_id : requestedClass;
    if (!classId) return json({ entries: [] });
    const rows = await env.DB.prepare(`SELECT d.id,d.class_id,d.subject,d.entry_type,d.title,d.details,d.due_date,d.diary_date,d.created_at,u.name AS teacher_name,
      COALESCE(h.completed,0) AS completed
      FROM diary_entries d JOIN users u ON u.id=d.created_by
      LEFT JOIN homework_status h ON h.entry_id=d.id AND h.student_id=?
      WHERE d.class_id=? ORDER BY d.diary_date DESC,d.created_at DESC LIMIT 150`).bind(user.role === 'student' ? user.id : '', classId).all();
    return json({ entries: rows.results || [] });
  }

  if (path === '/api/diary' && method === 'POST') {
    if (!requireRole(user, ['teacher','admin'])) return json({ error: 'Only teachers and admins can publish diary entries.' }, 403);
    const data = await body(request); const classId = text(data.classId, 64); const subject = text(data.subject, 80);
    const title = text(data.title, 140); const details = text(data.details, 3000); const type = ['homework','test','notice'].includes(data.entryType) ? data.entryType : 'homework';
    const diaryDate = text(data.diaryDate, 10); const dueDate = text(data.dueDate, 10) || null;
    if (!classId || !subject || !title || !details || !/^\d{4}-\d{2}-\d{2}$/.test(diaryDate)) return json({ error: 'Complete all required diary fields.' }, 400);
    const cls = await env.DB.prepare('SELECT id FROM classes WHERE id=? AND active=1').bind(classId).first();
    if (!cls) return json({ error: 'Class not found.' }, 404);
    const entryId = id();
    await env.DB.prepare('INSERT INTO diary_entries(id,class_id,subject,entry_type,title,details,due_date,diary_date,created_by) VALUES(?,?,?,?,?,?,?,?,?)')
      .bind(entryId,classId,subject,type,title,details,dueDate,diaryDate,user.id).run();
    return json({ ok: true, id: entryId }, 201);
  }

  if (path.startsWith('/api/diary/') && path.endsWith('/complete') && method === 'POST') {
    if (user.role !== 'student') return json({ error: 'Only students can update homework status.' }, 403);
    const entryId = path.split('/')[3]; const data = await body(request); const completed = data.completed ? 1 : 0;
    const entry = await env.DB.prepare('SELECT id FROM diary_entries WHERE id=? AND class_id=?').bind(entryId,user.class_id).first();
    if (!entry) return json({ error: 'Diary entry not found for your class.' }, 404);
    await env.DB.prepare(`INSERT INTO homework_status(id,entry_id,student_id,completed) VALUES(?,?,?,?)
      ON CONFLICT(entry_id,student_id) DO UPDATE SET completed=excluded.completed,updated_at=CURRENT_TIMESTAMP`).bind(id(),entryId,user.id,completed).run();
    return json({ ok: true });
  }

  if (path === '/api/announcements' && method === 'GET') {
    const audience = user.role === 'admin' ? ['all','teachers','students'] : ['all',user.role === 'teacher' ? 'teachers' : 'students'];
    const placeholders = audience.map(() => '?').join(',');
    const rows = await env.DB.prepare(`SELECT a.id,a.title,a.body,a.audience,a.created_at,u.name AS author FROM announcements a JOIN users u ON u.id=a.created_by WHERE a.audience IN (${placeholders}) ORDER BY a.created_at DESC LIMIT 50`).bind(...audience).all();
    return json({ announcements: rows.results || [] });
  }

  if (path === '/api/announcements' && method === 'POST') {
    if (!requireRole(user,['admin','teacher'])) return json({ error: 'Not allowed.' },403);
    const data = await body(request); const title = text(data.title,140); const content = text(data.body,3000); const audience = ['all','teachers','students'].includes(data.audience) ? data.audience : 'all';
    if (!title || !content) return json({ error: 'Title and message are required.' },400);
    await env.DB.prepare('INSERT INTO announcements(id,title,body,audience,created_by) VALUES(?,?,?,?,?)').bind(id(),title,content,audience,user.id).run();
    return json({ok:true},201);
  }

  if (path === '/api/admin/classes' && method === 'GET') {
    if (user.role !== 'admin') return json({error:'Admin access required.'},403);
    const rows = await env.DB.prepare('SELECT id,name,active,created_at FROM classes ORDER BY name').all();
    return json({classes:rows.results || []});
  }
  if (path === '/api/admin/classes' && method === 'POST') {
    if (user.role !== 'admin') return json({error:'Admin access required.'},403);
    const data = await body(request); const name = text(data.name,60);
    if (name.length < 1) return json({error:'Class name is required.'},400);
    try { await env.DB.prepare('INSERT INTO classes(id,name) VALUES(?,?)').bind(id(),name).run(); }
    catch { return json({error:'This class already exists.'},409); }
    return json({ok:true},201);
  }
  if (path.startsWith('/api/admin/classes/') && method === 'PATCH') {
    if (user.role !== 'admin') return json({error:'Admin access required.'},403);
    const classId = path.split('/')[4]; const data = await body(request); const name = text(data.name,60);
    if (name) { try { await env.DB.prepare('UPDATE classes SET name=? WHERE id=?').bind(name,classId).run(); } catch { return json({error:'Class name already exists.'},409); } }
    if (typeof data.active === 'boolean') await env.DB.prepare('UPDATE classes SET active=? WHERE id=?').bind(data.active?1:0,classId).run();
    return json({ok:true});
  }
  if (path === '/api/admin/users' && method === 'GET') {
    if (user.role !== 'admin') return json({error:'Admin access required.'},403);
    const rows = await env.DB.prepare('SELECT u.id,u.name,u.email,u.role,u.status,u.created_at,c.name AS class_name FROM users u LEFT JOIN classes c ON c.id=u.class_id ORDER BY u.created_at DESC LIMIT 300').all();
    return json({users:rows.results || []});
  }
  if (path.startsWith('/api/admin/users/') && method === 'PATCH') {
    if (user.role !== 'admin') return json({error:'Admin access required.'},403);
    const targetId = path.split('/')[4]; const data = await body(request);
    if (!['active','pending','disabled'].includes(data.status)) return json({error:'Invalid account status.'},400);
    await env.DB.prepare('UPDATE users SET status=? WHERE id=? AND role<>\'admin\'').bind(data.status,targetId).run();
    return json({ok:true});
  }
  if (path === '/api/admin/teacher-codes' && method === 'POST') {
    if (user.role !== 'admin') return json({error:'Admin access required.'},403);
    const data = await body(request); const uses = Math.max(1,Math.min(100,Number(data.uses)||1));
    const code = `CPS-${crypto.randomUUID().replaceAll('-','').slice(0,10).toUpperCase()}`;
    await env.DB.prepare('INSERT INTO teacher_codes(id,code_hash,uses_left,created_by) VALUES(?,?,?,?)').bind(id(),await sha256(code),uses,user.id).run();
    return json({ok:true,code,uses},201);
  }

  return json({error:'API route not found.'},404);
}
async function createSession(userId, env, cookieName) {
  const token = b64(crypto.getRandomValues(new Uint8Array(32))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
  const days = Math.max(1,Math.min(30,Number(env.SESSION_DAYS)||7));
  const expires = new Date(Date.now()+days*86400000).toISOString().replace('T',' ').slice(0,19);
  await env.DB.prepare('INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)').bind(id(),userId,await sha256(token),expires).run();
  const user = await env.DB.prepare('SELECT u.id,u.name,u.email,u.role,u.status,u.class_id,c.name AS class_name FROM users u LEFT JOIN classes c ON c.id=u.class_id WHERE u.id=?').bind(userId).first();
  return json({ok:true,user},200,{'set-cookie':cookie(cookieName,token,days*86400)});
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try { return await handleApi(request,env); }
      catch (error) { console.error('API error',error); return json({error:'Server error. Please try again later.'},500); }
    }
    return env.ASSETS.fetch(request);
  }
};
