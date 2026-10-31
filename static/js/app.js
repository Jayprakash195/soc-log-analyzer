(() => {
  const $ = (id) => document.getElementById(id);
  const state = { result: null, filtered: [], charts: {}, file: null };
  const fileInput = $('logFile'), dropZone = $('dropZone'), analyzeBtn = $('analyzeBtn');

  function showNotice(message, type = 'success') {
    const el = $('notice'); el.textContent = message; el.className = `notice ${type}`;
  }
  function clearNotice() { $('notice').className = 'notice hidden'; $('notice').textContent = ''; }
  function safeText(value) { return value == null ? '' : String(value); }
  function setFile(file) {
    state.file = file || null;
    if (!file) { $('selectedFile').classList.add('hidden'); $('selectedFile').textContent = ''; analyzeBtn.disabled = true; return; }
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['log', 'txt'].includes(ext)) { state.file = null; $('selectedFile').classList.remove('hidden'); $('selectedFile').textContent = 'Unsupported file type. Choose a .log or .txt file.'; analyzeBtn.disabled = true; return; }
    $('selectedFile').classList.remove('hidden'); $('selectedFile').textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
    analyzeBtn.disabled = file.size === 0;
  }
  $('browseBtn').addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('click', (event) => { if (event.target.id !== 'browseBtn') fileInput.click(); });
  dropZone.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); fileInput.click(); } });
  fileInput.addEventListener('change', () => setFile(fileInput.files[0]));
  ['dragenter', 'dragover'].forEach(type => dropZone.addEventListener(type, e => { e.preventDefault(); dropZone.classList.add('dragover'); }));
  ['dragleave', 'drop'].forEach(type => dropZone.addEventListener(type, e => { e.preventDefault(); dropZone.classList.remove('dragover'); }));
  dropZone.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; setFile(f); });

  async function requestJson(url, options = {}) {
    const response = await fetch(url, options);
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status}).`);
    return body;
  }
  async function loadSample() {
    clearNotice(); $('sampleBtn').disabled = true; $('sampleBtn').textContent = 'Loading…';
    try { const data = await requestJson('/api/sample'); renderResult(data); showNotice('Fictional sample data loaded. Results are clearly labelled as sample data.', 'success'); }
    catch (err) { showNotice(err.message, 'error'); }
    finally { $('sampleBtn').disabled = false; $('sampleBtn').textContent = 'Load sample data'; }
  }
  $('sampleBtn').addEventListener('click', loadSample);
  $('uploadForm').addEventListener('submit', async event => {
    event.preventDefault(); if (!state.file) return;
    clearNotice(); analyzeBtn.disabled = true; analyzeBtn.textContent = 'Analyzing…';
    const form = new FormData(); form.append('file', state.file); form.append('year', $('yearInput').value);
    try { const data = await requestJson('/api/analyze', { method: 'POST', body: form }); renderResult(data); showNotice('Log analysis completed. Review findings before taking action.', 'success'); }
    catch (err) { showNotice(err.message, 'error'); }
    finally { analyzeBtn.textContent = 'Analyze log →'; analyzeBtn.disabled = !state.file; }
  });

  function renderResult(data) {
    state.result = data; const s = data.summary || {};
    $('totalEvents').textContent = fmt(s.total_events); $('failedLogins').textContent = fmt(s.failed_logins);
    $('successfulLogins').textContent = fmt(s.successful_logins); $('uniqueIps').textContent = fmt(s.unique_source_ips);
    $('findingCount').textContent = fmt(s.findings); $('highCount').textContent = `High severity: ${fmt((s.severity_counts || {}).High || 0)}`;
    $('sourceBadge').textContent = data.sample_data ? 'SAMPLE DATA' : 'UPLOADED LOG';
    $('sourceBadge').className = `badge ${data.sample_data ? 'sample' : 'uploaded'}`;
    $('datasetLabel').textContent = data.sample_data ? 'Showing bundled fictional SSH authentication data.' : 'Showing analysis results from your uploaded log.';
    ['jsonBtn','csvBtn','htmlBtn','blocklistBtn'].forEach(id => $(id).disabled = false);
    $('jsonBtn').onclick = () => download(data.reports.json); $('csvBtn').onclick = () => download(data.reports.csv);
    $('htmlBtn').onclick = () => window.open(data.reports.html, '_blank', 'noopener'); $('blocklistBtn').onclick = () => download(data.reports.blocklist);
    fillTypeFilter(data.findings || []); renderFindings(); renderCharts(s, data.findings || []);
  }
  function fmt(n) { return Number.isFinite(Number(n)) ? Number(n).toLocaleString() : '—'; }
  function fillTypeFilter(findings) {
    const select = $('typeFilter'), old = select.value; select.replaceChildren(new Option('All detections', 'all'));
    [...new Set(findings.map(f => f.type))].sort().forEach(type => select.add(new Option(type, type)));
    if ([...select.options].some(o => o.value === old)) select.value = old;
  }
  function renderFindings() {
    if (!state.result) return;
    const q = $('searchInput').value.toLowerCase(), severity = $('severityFilter').value, type = $('typeFilter').value;
    const findings = (state.result.findings || []).filter(f => {
      const hay = [f.ip, f.user, f.detail, f.type, f.mitre].join(' ').toLowerCase();
      return hay.includes(q) && (severity === 'all' || f.severity === severity) && (type === 'all' || f.type === type);
    });
    state.filtered = findings; const body = $('findingsBody'); body.replaceChildren();
    if (!findings.length) { const tr = document.createElement('tr'), td = document.createElement('td'); td.colSpan = 8; td.className = 'table-empty'; td.textContent = 'No findings match the current filters.'; tr.append(td); body.append(tr); }
    findings.forEach(f => {
      const tr = document.createElement('tr');
      const sev = document.createElement('td'), pill = document.createElement('span'); pill.className = `severity-pill ${String(f.severity || '').toLowerCase()}`; pill.textContent = safeText(f.severity); sev.append(pill); tr.append(sev);
      addCell(tr, f.type); const ip = addCell(tr, f.ip); ip.className = 'ip-text'; addCell(tr, f.user); addCell(tr, f.count);
      const evidence = document.createElement('td'), detail = document.createElement('button'); detail.className = 'detail-button'; detail.type = 'button'; detail.textContent = safeText(f.detail); detail.addEventListener('click', () => openDetails(f)); evidence.append(detail); tr.append(evidence);
      addCell(tr, f.mitre); addCell(tr, `${safeText(f.first_seen)}${f.last_seen ? ' → ' + safeText(f.last_seen) : ''}`); body.append(tr);
    });
    $('resultCount').textContent = `${findings.length} of ${(state.result.findings || []).length} findings`;
  }
  function addCell(row, value) { const td = document.createElement('td'); td.textContent = safeText(value); row.append(td); return td; }
  ['searchInput','severityFilter','typeFilter'].forEach(id => $(id).addEventListener(id === 'searchInput' ? 'input' : 'change', renderFindings));
  $('clearFilters').addEventListener('click', () => { $('searchInput').value = ''; $('severityFilter').value = 'all'; $('typeFilter').value = 'all'; renderFindings(); });

  function renderCharts(summary, findings) {
    const emptyIds = ['authChartEmpty','severityChartEmpty','categoryChartEmpty','timelineChartEmpty'];
    if (typeof Chart === 'undefined') { emptyIds.forEach(id => { $(id).textContent = 'Charts require an internet connection to load Chart.js.'; $(id).classList.remove('hidden'); }); return; }
    emptyIds.forEach(id => $(id).classList.add('hidden'));
    Object.values(state.charts).forEach(chart => chart.destroy()); state.charts = {};
    state.charts.auth = new Chart($('authChart'), {type:'bar', data:{labels:['Failed','Successful'],datasets:[{data:[summary.failed_logins || 0,summary.successful_logins || 0],backgroundColor:['#ff707d','#45d6a0'],borderRadius:7,maxBarThickness:60}]},options:chartOptions(false)});
    const counts = {High:0,Medium:0,Low:0}; findings.forEach(f => { if (Object.hasOwn(counts,f.severity)) counts[f.severity]++; });
    if (!findings.length) $('severityChartEmpty').classList.remove('hidden');
    state.charts.severity = new Chart($('severityChart'), {type:'doughnut',data:{labels:Object.keys(counts),datasets:[{data:Object.values(counts),backgroundColor:['#ff707d','#ffbd69','#45d6a0'],borderColor:'#111c31',borderWidth:4}]},options:{...chartOptions(true),plugins:{legend:{position:'bottom',labels:{color:'#aab7cc',usePointStyle:true,padding:18}},tooltip:{enabled:true}}}});
    const cats = summary.category_counts || {};
    if (!Object.keys(cats).length) $('categoryChartEmpty').classList.remove('hidden');
    state.charts.category = new Chart($('categoryChart'), {type:'bar',data:{labels:Object.keys(cats),datasets:[{data:Object.values(cats),backgroundColor:'#63a8ff',borderRadius:6}]},options:{...chartOptions(false),indexAxis:'y',scales:{x:{beginAtZero:true,ticks:{color:'#94a3b8'},grid:{color:'#25334b'}},y:{ticks:{color:'#94a3b8'},grid:{display:false}}}}});
    const timeline = summary.events_over_time || [];
    if (!timeline.length) $('timelineChartEmpty').classList.remove('hidden');
    state.charts.timeline = new Chart($('timelineChart'), {type:'line',data:{labels:timeline.map(x=>x.time),datasets:[{label:'Failed',data:timeline.map(x=>x.failed),borderColor:'#ff707d',backgroundColor:'#ff707d22',fill:true,tension:.25},{label:'Successful',data:timeline.map(x=>x.successful),borderColor:'#45d6a0',backgroundColor:'#45d6a022',fill:true,tension:.25}]},options:{...chartOptions(false),plugins:{legend:{position:'bottom',labels:{color:'#aab7cc',usePointStyle:true}},tooltip:{enabled:true}},scales:{x:{ticks:{color:'#94a3b8',maxTicksLimit:6,maxRotation:0},grid:{display:false}},y:{beginAtZero:true,ticks:{color:'#94a3b8'},grid:{color:'#25334b'}}}}});
  }
  function chartOptions(horizontal) { return {responsive:true,maintainAspectRatio:false,indexAxis:horizontal?'y':'x',plugins:{legend:{display:false},tooltip:{enabled:true}},scales:horizontal?{}:{x:{ticks:{color:'#94a3b8'},grid:{display:false}},y:{beginAtZero:true,ticks:{color:'#94a3b8'},grid:{color:'#25334b'}}}}; }
  function openDetails(f) {
    $('modalTitle').textContent = safeText(f.type || 'Finding details'); const content = $('modalContent'); content.replaceChildren();
    const grid = document.createElement('div'); grid.className = 'detail-grid';
    [['Severity',f.severity],['Source IP',f.ip],['Username(s)',f.user],['Attempt count',f.count],['First seen',f.first_seen],['Last seen',f.last_seen],['Evidence',f.detail],['MITRE ATT&CK',f.mitre]].forEach(([label,value]) => { const item=document.createElement('div'), span=document.createElement('span'), b=document.createElement('b'); item.className='detail-item'; span.textContent=label; b.textContent=safeText(value || 'Not available'); item.append(span,b); grid.append(item); });
    content.append(grid); const note=document.createElement('p'); note.className='modal-note'; note.textContent='Analyst guidance: validate timestamps, source ownership, expected user activity, and related endpoint or network events before treating this finding as an incident.'; content.append(note); $('detailModal').classList.remove('hidden'); $('closeModal').focus();
  }
  $('closeModal').addEventListener('click', () => $('detailModal').classList.add('hidden'));
  $('detailModal').addEventListener('click', e => { if (e.target.id === 'detailModal') $('detailModal').classList.add('hidden'); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') $('detailModal').classList.add('hidden'); });
  function download(url) { if (!url) return; const a=document.createElement('a'); a.href=url; a.download=''; document.body.append(a); a.click(); a.remove(); }
  // Load a genuine sample analysis on first visit. Its SAMPLE DATA label remains visible.
  loadSample();
})();
