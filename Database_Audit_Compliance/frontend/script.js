// Database Audit & Compliance - frontend logic
// Talks to the C++ backend through /api/* endpoints. The role is only used to
// show/hide buttons; the SERVER is what really enforces permissions.

const $ = id => document.getElementById(id);
let token = sessionStorage.getItem('token');
let me    = JSON.parse(sessionStorage.getItem('me') || 'null');

const esc = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));   // prevents XSS from log data

const PERMS = {
  admin:   ['emp_add','emp_edit','emp_del','audit','compliance','users'],
  user:    ['emp_add','emp_edit'],
  auditor: ['audit','compliance']
};
const can = p => me && (PERMS[me.role] || []).includes(p);

// ---------------------------------------------------------------- API
async function api(path, method = 'GET', data = null) {
  const opts = { method, headers: { 'X-Auth-Token': token || '' } };
  let url = path;
  if (data) {
    const p = new URLSearchParams(data);
    if (method === 'GET') url += '?' + p;
    else { opts.body = p; opts.headers['Content-Type'] = 'application/x-www-form-urlencoded'; }
  }
  let r, j;
  try { r = await fetch(url, opts); j = await r.json(); }
  catch { return { ok: false, message: 'Cannot reach the server.' }; }
  if (r.status === 401 && token) { clearSession(); showLogin('Session expired. Please log in again.'); }
  return j;
}

function toast(msg, ok = true) {
  const t = $('toast');
  t.textContent = msg; t.className = 'toast ' + (ok ? 'ok' : 'err'); t.hidden = false;
  clearTimeout(toast.h); toast.h = setTimeout(() => t.hidden = true, 3500);
}

function table(cols, rows, extra) {
  if (!rows.length) return '<p class="empty">No records found.</p>';
  const head = cols.map(c => `<th>${c[1]}</th>`).join('') + (extra ? '<th></th>' : '');
  const body = rows.map(r => '<tr>' + cols.map(c => {
    const v = r[c[0]];
    if (c[0] === 'status')  return `<td><span class="badge ${esc(v)}">${esc(v)}</span></td>`;
    if (c[0] === 'role')    return `<td><span class="badge role">${esc(v)}</span></td>`;
    return `<td>${esc(v)}</td>`;
  }).join('') + (extra ? `<td class="actions">${extra(r)}</td>` : '') + '</tr>').join('');
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

// ---------------------------------------------------------------- login / logout
function clearSession() { token = null; me = null; sessionStorage.clear(); }
function showLogin(msg = '') { $('appView').hidden = true; $('loginView').hidden = false; $('loginError').textContent = msg; }

$('loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const j = await api('/api/login', 'POST', { username: $('loginUser').value.trim(), password: $('loginPass').value });
  if (!j.ok) { $('loginError').textContent = j.message; return; }
  token = j.token; me = { username: j.username, role: j.role };
  sessionStorage.setItem('token', token); sessionStorage.setItem('me', JSON.stringify(me));
  $('loginPass').value = ''; startApp();
});

$('logoutBtn').addEventListener('click', async () => { await api('/api/logout', 'POST'); clearSession(); showLogin(); });

// ---------------------------------------------------------------- tabs
const TABS = [
  ['employees', 'Employees',    () => true],
  ['audit',     'Audit Log',    () => can('audit')],
  ['changes',   'Data Changes', () => can('audit')],
  ['compliance','Compliance',   () => can('compliance')],
  ['users',     'Users',        () => can('users')]
];

function startApp() {
  $('loginView').hidden = true; $('appView').hidden = false;
  $('whoami').innerHTML = `${esc(me.username)} <span class="badge role">${esc(me.role)}</span>`;
  $('empFormCard').hidden = !can('emp_add');
  $('tabs').innerHTML = '';
  TABS.filter(t => t[2]()).forEach(t => {
    const b = document.createElement('button');
    b.textContent = t[1]; b.dataset.tab = t[0]; b.onclick = () => openTab(t[0]);
    $('tabs').appendChild(b);
  });
  openTab('employees');
}

function openTab(name) {
  TABS.forEach(t => $('tab-' + t[0]).hidden = (t[0] !== name));
  document.querySelectorAll('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  ({ employees: loadEmployees, audit: loadAudit, changes: loadChanges, compliance: loadCompliance, users: loadUsers })[name]();
}

// ---------------------------------------------------------------- employees
async function loadEmployees() {
  const j = await api('/api/employees', 'GET', { search: $('empSearch').value.trim() });
  if (!j.ok) { $('empTable').innerHTML = `<p class="error">${esc(j.message)}</p>`; return; }
  $('empTable').innerHTML = table(
    [['id','ID'],['name','Name'],['department','Department'],['email','Email'],['salary','Salary']],
    j.data,
    (can('emp_edit') || can('emp_del')) ? r =>
      (can('emp_edit') ? `<button class="btn small" data-edit='${esc(JSON.stringify(r))}'>Edit</button>` : '') +
      (can('emp_del')  ? `<button class="btn small danger" data-del="${esc(r.id)}">Delete</button>` : '') : null);
}
$('empSearch').addEventListener('input', () => { clearTimeout(loadEmployees.h); loadEmployees.h = setTimeout(loadEmployees, 300); });

$('empTable').addEventListener('click', async e => {
  if (e.target.dataset.edit) {
    const r = JSON.parse(e.target.dataset.edit);
    $('empId').value = r.id; $('empName').value = r.name; $('empDept').value = r.department;
    $('empEmail').value = r.email; $('empSalary').value = r.salary;
    $('empFormTitle').textContent = 'Edit employee #' + r.id; $('empCancel').hidden = false;
    $('empFormCard').hidden = !can('emp_edit'); scrollTo({ top: 0, behavior: 'smooth' });
  }
  if (e.target.dataset.del && confirm('Delete this employee? This action will be audited.')) {
    const j = await api('/api/employees/delete', 'POST', { id: e.target.dataset.del });
    toast(j.message, j.ok); loadEmployees();
  }
});

function resetEmpForm() {
  $('empForm').reset(); $('empId').value = ''; $('empFormTitle').textContent = 'Add employee';
  $('empCancel').hidden = true; $('empFormCard').hidden = !can('emp_add');
}
$('empCancel').addEventListener('click', resetEmpForm);
$('empForm').addEventListener('submit', async e => {
  e.preventDefault();
  const data = { name: $('empName').value.trim(), department: $('empDept').value.trim(),
                 email: $('empEmail').value.trim(), salary: $('empSalary').value };
  const editing = $('empId').value;
  if (editing) data.id = editing;
  const j = await api(editing ? '/api/employees/update' : '/api/employees/add', 'POST', data);
  toast(j.message, j.ok);
  if (j.ok) { resetEmpForm(); loadEmployees(); }
});

// ---------------------------------------------------------------- audit log / data changes
async function loadAudit() {
  const j = await api('/api/audit', 'GET', { user: $('fUser').value.trim(), action: $('fAction').value, status: $('fStatus').value });
  $('auditTable').innerHTML = j.ok
    ? table([['id','#'],['ts','Time'],['username','User'],['role','Role'],['action','Action'],['table_name','Table'],
             ['record_id','Record'],['details','Details'],['status','Result'],['ip_address','IP']], j.data)
    : `<p class="error">${esc(j.message)}</p>`;
}
$('fApply').addEventListener('click', loadAudit);

async function loadChanges() {
  const j = await api('/api/changes');
  $('changesTable').innerHTML = j.ok
    ? table([['id','#'],['ts','Time'],['table_name','Table'],['record_id','Record'],['operation','Operation'],
             ['old_value','Old value'],['new_value','New value']], j.data)
    : `<p class="error">${esc(j.message)}</p>`;
}

// ---------------------------------------------------------------- compliance
async function loadCompliance() {
  const j = await api('/api/compliance');
  if (!j.ok) { $('complianceList').innerHTML = `<p class="error">${esc(j.message)}</p>`; return; }
  const n = s => j.data.filter(r => r.status === s).length;
  $('summary').innerHTML =
    `<div class="PASS"><span>${n('PASS')}</span>Passed</div>` +
    `<div class="WARN"><span>${n('WARN')}</span>Warnings</div>` +
    `<div class="FAIL"><span>${n('FAIL')}</span>Failed</div>`;
  $('complianceList').innerHTML = j.data.map(r =>
    `<div class="check"><span class="badge ${esc(r.status)}">${esc(r.status)}</span>
     <div><b>${esc(r.check)}</b><small>${esc(r.detail)}</small></div></div>`).join('');
}
$('runCompliance').addEventListener('click', loadCompliance);

// ---------------------------------------------------------------- users (admin)
async function loadUsers() {
  const j = await api('/api/users');
  $('usersTable').innerHTML = j.ok
    ? table([['id','ID'],['username','Username'],['role','Role'],['failed_attempts','Failed logins'],
             ['locked','Locked (1=yes)'],['created_at','Created']], j.data,
        r => r.locked === '1' ? `<button class="btn small" data-unlock="${esc(r.username)}">Unlock</button>` : '')
    : `<p class="error">${esc(j.message)}</p>`;
}
$('usersTable').addEventListener('click', async e => {
  if (!e.target.dataset.unlock) return;
  const j = await api('/api/users/unlock', 'POST', { username: e.target.dataset.unlock });
  toast(j.message, j.ok); loadUsers();
});
$('userForm').addEventListener('submit', async e => {
  e.preventDefault();
  const j = await api('/api/users/add', 'POST', { username: $('uName').value.trim(), password: $('uPass').value, role: $('uRole').value });
  toast(j.message, j.ok);
  if (j.ok) { $('userForm').reset(); loadUsers(); }
});

// ---------------------------------------------------------------- boot
if (token && me) startApp(); else showLogin();
