// Buckets & Budgets view (owner: Saged Ehab, 244694).
// Talks only to /api/buckets/*; the budget numbers come from the backend (never computed here).
const BucketsView = {
  buckets: [],

  init() {
    const month = document.getElementById('bucket-month');
    month.value = UI.thisMonth();
    month.addEventListener('change', () => this.load());

    const form = document.getElementById('form-bucket');
    form.addEventListener('submit', (e) => { e.preventDefault(); this.save(form); });
    document.getElementById('bucket-cancel').addEventListener('click', () => this.resetForm());
    form.templateId.addEventListener('change', () => {
      const opt = form.templateId.selectedOptions[0];
      if (opt && opt.dataset.limit) {
        form.name.value = opt.textContent.replace(/ \(.*\)$/, '');
        form.monthlyLimit.value = opt.dataset.limit;
      }
    });

    const transfer = document.getElementById('form-transfer');
    transfer.addEventListener('submit', (e) => { e.preventDefault(); this.transfer(transfer); });
  },

  month() { return document.getElementById('bucket-month').value || UI.thisMonth(); },

  async load() {
    try {
      const [data, alerts, templates, transfers] = await Promise.all([
        Api.get('/api/buckets', { month: this.month(), includeArchived: 'true' }),
        Api.get('/api/buckets/alerts', { unacknowledged: 'true' }),
        Api.get('/api/buckets/templates'),
        Api.get('/api/buckets/transfers', { month: this.month() })
      ]);
      this.buckets = data.items;
      this.renderList(data);
      this.renderAlerts(alerts.items);
      this.renderTemplates(templates.items);
      this.renderTransfers(transfers.items);
      App.bucketsChanged(this.buckets.filter((b) => b.status === 'active'));
    } catch (error) { UI.fail(error); }
  },

  renderList(data) {
    const list = UI.clear(document.getElementById('bucket-list'));
    const cur = (UI.user() || {}).baseCurrency;
    if (!data.items.length) list.append(UI.el('p', { class: 'muted', text: 'No buckets yet. Create your first one on the right.' }));
    for (const b of data.items) {
      const s = b.budget;
      const archived = b.status === 'archived';
      const card = UI.el('div', { class: 'bucket', style: `border-left-color:${/^#[0-9a-fA-F]{6}$/.test(b.color) ? b.color : '#2e7d6b'}` },
        UI.el('div', { class: 'top' },
          UI.el('span', { class: 'name', text: b.name }),
          UI.el('span', { class: `badge ${archived ? 'archived' : s.state}`, text: archived ? 'Archived' : UI.stateLabel[s.state] })),
        UI.el('div', { class: 'nums', text: `${UI.money(s.spent)} of ${UI.money(s.effectiveLimit, cur)} spent · ${UI.money(s.remaining)} left` }),
        UI.el('div', { class: `bar ${s.state}` }, UI.el('span', { style: `width:${Math.min(100, s.percentUsed)}%` })),
        UI.el('div', { class: 'meta' },
          UI.el('span', { text: [
            `limit ${UI.money(s.monthlyLimit)}`,
            s.rolloverIn ? `+${UI.money(s.rolloverIn)} rolled over` : '',
            s.transfersIn ? `+${UI.money(s.transfersIn)} moved in` : '',
            s.transfersOut ? `-${UI.money(s.transfersOut)} moved out` : '',
            b.hardLimit ? 'hard limit' : `alert at ${b.alertThreshold}%`
          ].filter(Boolean).join(' · ') }),
          UI.el('span', {},
            archived
              ? UI.el('button', { class: 'link', text: 'Restore', onclick: () => this.action(b, 'restore') })
              : [UI.el('button', { class: 'link', text: 'Edit', onclick: () => this.edit(b) }),
                UI.el('button', { class: 'link', text: 'Archive', onclick: () => this.action(b, 'archive') })],
            UI.el('button', { class: 'link danger', text: 'Delete', onclick: () => this.remove(b) }))));
      list.append(card);
    }
    document.getElementById('bucket-totals').textContent =
      `Total for ${data.month}: ${UI.money(data.totals.spent)} spent of ${UI.money(data.totals.effectiveLimit, cur)} (${UI.money(data.totals.remaining)} left)`;
  },

  renderAlerts(items) {
    const box = UI.clear(document.getElementById('alerts-box'));
    for (const a of items) {
      box.append(UI.el('div', { class: `alert ${a.level}` },
        UI.el('span', { text: `${a.level === 'OVER_LIMIT' ? 'Over budget' : 'Near limit'}: "${a.bucketName}" reached ${UI.pct(a.percentUsed)} of its ${a.month} budget.` }),
        UI.el('button', { class: 'link', text: 'Dismiss', onclick: async () => {
          try { await Api.patch(`/api/buckets/alerts/${a.id}`, { acknowledged: true }); this.load(); } catch (e) { UI.fail(e); }
        } })));
    }
  },

  renderTemplates(items) {
    const sel = document.getElementById('form-bucket').templateId;
    UI.clear(sel).append(UI.el('option', { value: '', text: 'None' }));
    for (const t of items) sel.append(UI.el('option', { value: t.id, 'data-limit': t.suggestedLimit, text: `${t.name} (${UI.money(t.suggestedLimit)})` }));
  },

  renderTransfers(items) {
    const form = document.getElementById('form-transfer');
    const active = this.buckets.filter((b) => b.status === 'active');
    for (const sel of [form.fromBucketId, form.toBucketId]) {
      const keep = sel.value;
      UI.clear(sel);
      for (const b of active) sel.append(UI.el('option', { value: b.id, text: `${b.name} (${UI.money(b.budget.remaining)} left)` }));
      if (keep) sel.value = keep;
    }
    const list = UI.clear(document.getElementById('transfer-list'));
    for (const t of items) list.append(UI.el('li', {}, UI.el('span', { text: `${t.fromBucketName} → ${t.toBucketName}` }), UI.el('span', { text: UI.money(t.amount) })));
  },

  edit(b) {
    const form = document.getElementById('form-bucket');
    form.id.value = b.id;
    form.name.value = b.name;
    form.monthlyLimit.value = b.monthlyLimit;
    form.alertThreshold.value = b.alertThreshold;
    form.rollover.checked = b.rollover;
    form.hardLimit.checked = b.hardLimit;
    form.color.value = b.color;
    form.templateId.closest('label').classList.add('hidden');
    document.getElementById('bucket-form-title').textContent = `Edit "${b.name}"`;
    document.getElementById('bucket-cancel').classList.remove('hidden');
  },

  resetForm() {
    const form = document.getElementById('form-bucket');
    form.reset();
    form.id.value = '';
    form.templateId.closest('label').classList.remove('hidden');
    document.getElementById('bucket-form-title').textContent = 'New bucket';
    document.getElementById('bucket-cancel').classList.add('hidden');
  },

  async save(form) {
    const d = UI.formData(form);
    const body = {
      name: d.name,
      monthlyLimit: Number(d.monthlyLimit),
      alertThreshold: Number(d.alertThreshold || 80),
      rollover: form.rollover.checked,
      hardLimit: form.hardLimit.checked,
      color: d.color
    };
    if (!d.name || d.monthlyLimit === '') { UI.toast('Name and monthly budget are required.', true); return; }
    try {
      if (d.id) {
        const res = await Api.patch(`/api/buckets/${d.id}`, body);
        UI.toast(res.warning || 'Bucket updated.', Boolean(res.warning));
      } else {
        if (d.templateId) body.templateId = d.templateId;
        await Api.post('/api/buckets', body);
        UI.toast('Bucket created.');
      }
      this.resetForm();
      this.load();
    } catch (error) { UI.fail(error); }
  },

  async action(b, what) {
    try { await Api.post(`/api/buckets/${b.id}/${what}`); UI.toast(`Bucket ${what === 'archive' ? 'archived' : 'restored'}.`); this.load(); } catch (e) { UI.fail(e); }
  },

  async remove(b) {
    if (!window.confirm(`Delete "${b.name}"? This cannot be undone.`)) return;
    try { await Api.del(`/api/buckets/${b.id}`); UI.toast('Bucket deleted.'); this.load(); } catch (e) { UI.fail(e); }
  },

  async transfer(form) {
    const d = UI.formData(form);
    try {
      await Api.post('/api/buckets/transfers', {
        fromBucketId: d.fromBucketId, toBucketId: d.toBucketId, amount: Number(d.amount), month: this.month(), ...(d.note ? { note: d.note } : {})
      });
      form.amount.value = '';
      form.note.value = '';
      UI.toast('Budget moved.');
      this.load();
    } catch (e) { UI.fail(e); }
  }
};
