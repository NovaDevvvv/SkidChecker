import { analyzeJarInBrowser, getBrowserCatalog } from './browser-scan.js';

const form = document.querySelector('#scan-form');
const input = document.querySelector('#modJar');
const button = document.querySelector('#submit-button');
const selectedFile = document.querySelector('#selected-file');

const fernflowerStatus = document.querySelector('#fernflower-status');

const progressLabel = document.querySelector('#progress-label');
const progressValue = document.querySelector('#progress-value');
const progressFill = document.querySelector('#progress-fill');
const progressRing = document.querySelector('#progress-ring');
const scanStage = document.querySelector('#scan-stage');
const scanDetail = document.querySelector('#scan-detail');
const progressSteps = document.querySelector('#progress-steps');

const resultStatus = document.querySelector('#result-status');
const resultTitle = document.querySelector('#result-title');
const resultSummary = document.querySelector('#result-summary');
const scorePill = document.querySelector('#score-pill');
const certaintyValue = document.querySelector('#certainty-value');
const verdictValue = document.querySelector('#verdict-value');
const familyValue = document.querySelector('#family-value');
const filesValue = document.querySelector('#files-value');
const checksValue = document.querySelector('#checks-value');

const detectionsContainer = document.querySelector('#detections');
const checksGrid = document.querySelector('#checks-grid');
const catalogGrid = document.querySelector('#catalog-grid');

const stepTemplate = document.querySelector('#step-template');
const detectionTemplate = document.querySelector('#detection-template');
const checkTemplate = document.querySelector('#check-template');
const catalogTemplate = document.querySelector('#catalog-template');

const runtimeConfig = window.SKIDCHECKER_CONFIG || {};
const apiBaseUrl = normalizeApiBaseUrl(runtimeConfig.apiBaseUrl || '');

let activeJobId = null;
let pollTimer = null;

boot();
bindEvents();

function bindEvents() {
  input.addEventListener('change', () => {
    selectedFile.textContent = input.files?.[0]?.name || 'No file selected';
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    if (!input.files?.length) {
      return;
    }

    clearPolling();

    const formData = new FormData();
    formData.append('modJar', input.files[0]);

    button.disabled = true;
    button.textContent = 'Preparing analysis...';
    setProgressShell({
      label: 'Queued',
      progress: 4,
      stage: 'Preparing analysis',
      detail: `${input.files[0].name} has been queued for decompilation and rule evaluation.`
    });

    try {
      if (!apiBaseUrl) {
        await runBrowserModeAnalysis(input.files[0]);
        return;
      }

      const response = await apiFetch('/api/scan', {
        method: 'POST',
        body: formData
      });
      const payload = await response.json();

      if (!response.ok) {
        throw new Error(payload.error || 'Scan failed.');
      }

      activeJobId = payload.id;
      renderJob(payload);
      button.textContent = 'Analysis in progress...';
      startPolling(payload.id);
    } catch (error) {
      button.disabled = false;
      button.textContent = 'Start analysis';
      showErrorState(input.files[0].name, error.message);
    }
  });
}

async function boot() {
  if (!apiBaseUrl) {
    fernflowerStatus.textContent = 'Browser mode';
    renderCatalog(getBrowserCatalog());
    return;
  }

  try {
    const [healthResponse, catalogResponse] = await Promise.all([
      apiFetch('/api/health'),
      apiFetch('/api/catalog')
    ]);
    const healthPayload = await healthResponse.json();
    const catalogPayload = await catalogResponse.json();

    fernflowerStatus.textContent = healthPayload.fernflowerReady ? 'Ready' : 'Missing jar';
    renderCatalog(catalogPayload.checks || []);
  } catch {
    fernflowerStatus.textContent = apiBaseUrl ? 'API unavailable' : 'API not configured';
    catalogGrid.className = 'catalog-grid empty-state';
    catalogGrid.textContent = apiBaseUrl
      ? 'The check catalog is currently unavailable.'
      : 'Set window.SKIDCHECKER_CONFIG.apiBaseUrl in config.js to connect this GitHub Pages frontend to a hosted API.';
  }
}

async function runBrowserModeAnalysis(file) {
  const placeholderJob = {
    fileName: file.name,
    status: 'running',
    progress: 4,
    currentStep: 'Preparing browser analysis',
    steps: []
  };

  renderJob(placeholderJob);
  button.textContent = 'Analysis in progress...';

  const result = await analyzeJarInBrowser(file, ({ progress, currentStep, steps }) => {
    renderJob({
      fileName: file.name,
      status: 'running',
      progress,
      currentStep,
      steps
    });
  });

  renderJob({
    fileName: file.name,
    status: 'complete',
    progress: 100,
    currentStep: 'Analysis complete',
    steps: [
      { id: 'load', label: 'Load archive', confidence: 100, status: 'done', detail: 'Completed.' },
      { id: 'enumerate', label: 'Enumerate files', confidence: 94, status: 'done', detail: 'Completed.' },
      { id: 'checks', label: 'Run browser checks', confidence: 78, status: 'done', detail: 'Completed.' },
      { id: 'score', label: 'Score verdict', confidence: 76, status: 'done', detail: 'Completed.' }
    ],
    result
  });

  button.disabled = false;
  button.textContent = 'Start analysis';
}

function startPolling(jobId) {
  pollTimer = window.setInterval(async () => {
    try {
      const response = await apiFetch(`/api/scan/${jobId}`);
      const payload = await response.json();

      if (!response.ok) {
        throw new Error(payload.error || 'Status check failed.');
      }

      renderJob(payload);

      if (payload.status === 'complete' || payload.status === 'failed') {
        clearPolling();
        button.disabled = false;
        button.textContent = 'Start analysis';
      }
    } catch (error) {
      clearPolling();
      button.disabled = false;
      button.textContent = 'Start analysis';
      showErrorState(activeJobId || 'Scan', error.message);
    }
  }, 850);
}

function clearPolling() {
  if (pollTimer) {
    window.clearInterval(pollTimer);
    pollTimer = null;
  }
}

function renderJob(job) {
  setProgressShell({
    label: job.status,
    progress: job.progress,
    stage: job.currentStep,
    detail: buildJobDetail(job)
  });
  renderSteps(job.steps || []);

  if (job.status === 'complete' && job.result) {
    renderResult(job.result);
    return;
  }

  if (job.status === 'failed') {
    showErrorState(job.fileName, job.error || 'Scan failed.');
    return;
  }

  renderPendingResult(job.fileName, job.status, job.currentStep);
}

function buildJobDetail(job) {
  if (job.status === 'failed') {
    return job.error || 'The analysis did not complete successfully.';
  }

  const activeStep = (job.steps || []).find((step) => step.status === 'active');
  if (activeStep?.detail) {
    return activeStep.detail;
  }

  return 'The file is being decompiled and evaluated against the active detection rules.';
}

function setProgressShell({ label, progress, stage, detail }) {
  progressLabel.textContent = humanize(label);
  progressValue.textContent = `${progress}%`;
  progressFill.style.width = `${progress}%`;
  progressRing.style.setProperty('--progress', `${progress}%`);
  scanStage.textContent = stage;
  scanDetail.textContent = detail;
}

function renderSteps(steps) {
  progressSteps.replaceChildren();

  if (!steps.length) {
    return;
  }

  for (const step of steps) {
    const node = stepTemplate.content.cloneNode(true);
    const item = node.querySelector('.step-item');
    item.classList.add(step.status);
    node.querySelector('.step-title').textContent = step.label;
    node.querySelector('.step-confidence').textContent = `${step.confidence}% confidence`;
    node.querySelector('.step-detail').textContent = step.detail || defaultStepDetail(step.status);
    progressSteps.append(node);
  }
}

function renderPendingResult(fileName, status, currentStep) {
  resultStatus.textContent = humanize(status);
  resultTitle.textContent = fileName || 'Awaiting result';
  resultSummary.textContent = currentStep || 'Analysis has started, but no verdict is available yet.';
  scorePill.textContent = '--';
  certaintyValue.textContent = '--';
  verdictValue.textContent = humanize(status);
  familyValue.textContent = '-';
  filesValue.textContent = '-';
  checksValue.textContent = '-';
  detectionsContainer.className = 'detections empty-state';
  detectionsContainer.textContent = 'Detections will appear here when analysis is complete.';
  checksGrid.className = 'checks-grid empty-state';
  checksGrid.textContent = 'The full check matrix will appear after source analysis completes.';
}

function renderResult(result) {
  resultStatus.textContent = humanize(result.verdict);
  resultTitle.textContent = result.fileName;
  resultSummary.textContent = buildSummary(result);
  scorePill.textContent = String(result.score ?? 0);
  certaintyValue.textContent = `${result.certainty ?? 0}%`;
  verdictValue.textContent = humanize(result.verdict);
  familyValue.textContent = result.primaryFamily || '-';
  filesValue.textContent = String(result.sourceFileCount ?? '-');
  checksValue.textContent = `${result.matchedCheckCount ?? 0}/${result.checks?.length ?? 0}`;

  renderDetections(result.detections || []);
  renderChecks(result.checks || []);
}

function renderDetections(detections) {
  detectionsContainer.replaceChildren();

  if (!detections.length) {
    detectionsContainer.className = 'detections empty-state';
    detectionsContainer.textContent = 'No matched signatures were identified in the decompiled source.';
    return;
  }

  detectionsContainer.className = 'detections';

  for (const detection of detections.sort((left, right) => right.confidence - left.confidence)) {
    const node = detectionTemplate.content.cloneNode(true);
    const severity = node.querySelector('.severity');
    severity.textContent = detection.severity;
    severity.classList.add(detection.severity);
    node.querySelector('.family').textContent = detection.family;
    node.querySelector('.confidence').textContent = `${detection.confidence}% certain`;
    node.querySelector('.detection-title').textContent = detection.label;
    node.querySelector('.description').textContent = detection.description;
    node.querySelector('.rationale').textContent = detection.rationale;
    node.querySelector('.file').textContent = detection.file;
    node.querySelector('.snippet').textContent = detection.snippet;
    detectionsContainer.append(node);
  }
}

function renderChecks(checks) {
  checksGrid.replaceChildren();

  if (!checks.length) {
    checksGrid.className = 'checks-grid empty-state';
    checksGrid.textContent = 'No checks are available for this analysis.';
    return;
  }

  checksGrid.className = 'checks-grid';

  for (const check of checks.sort(sortChecks)) {
    const node = checkTemplate.content.cloneNode(true);
    const card = node.querySelector('.check-card');
    card.classList.add(check.matched ? 'matched' : 'unmatched');

    const state = node.querySelector('.check-state');
    state.textContent = check.matched ? 'Matched' : 'Not detected';
    state.classList.add(check.matched ? 'matched' : 'unmatched');

    node.querySelector('.check-label').textContent = check.label;
    node.querySelector('.check-severity').textContent = check.severity;
    node.querySelector('.check-family').textContent = check.family;
    node.querySelector('.check-confidence').textContent = `${check.confidence}%`;
    node.querySelector('.check-rationale').textContent = check.rationale;

    const evidence = node.querySelector('.check-evidence');
    evidence.textContent = check.matched
      ? `${check.file}: ${check.evidence}`
      : 'No matching source fragment was identified in this analysis.';

    node.querySelector('.confidence-bar span').style.width = `${check.confidence}%`;
    checksGrid.append(node);
  }
}

function showErrorState(fileName, message) {
  setProgressShell({
    label: 'Failed',
    progress: 100,
    stage: 'Analysis failed',
    detail: message
  });

  resultStatus.textContent = 'Failed';
  resultTitle.textContent = fileName || 'Scan error';
  resultSummary.textContent = message;
  scorePill.textContent = '!!';
  certaintyValue.textContent = '--';
  verdictValue.textContent = 'Error';
  familyValue.textContent = '-';
  filesValue.textContent = '-';
  checksValue.textContent = '-';
  detectionsContainer.className = 'detections empty-state';
  detectionsContainer.textContent = 'The analysis failed before detections could be generated.';
  checksGrid.className = 'checks-grid empty-state';
  checksGrid.textContent = 'No per-check matrix is available because the analysis did not complete.';
}

function buildSummary(result) {
  if (!result.detections?.length) {
    return 'No signature matched strongly enough to raise an alert under the current ruleset.';
  }

  const strongest = [...result.detections].sort((left, right) => right.confidence - left.confidence)[0];
  return `${humanize(result.verdict)} with ${result.certainty}% certainty. Strongest hit: ${strongest.label} in ${strongest.file}.`;
}

function defaultStepDetail(status) {
  if (status === 'done') {
    return 'Completed.';
  }

  if (status === 'active') {
    return 'In progress.';
  }

  if (status === 'failed') {
    return 'Failed.';
  }

  return 'Pending.';
}

function sortChecks(left, right) {
  if (left.matched !== right.matched) {
    return left.matched ? -1 : 1;
  }

  return right.confidence - left.confidence;
}

function humanize(value) {
  if (!value) {
    return 'Unknown';
  }

  return String(value)
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

function apiFetch(path, options) {
  return fetch(`${apiBaseUrl}${path}`, options);
}

function normalizeApiBaseUrl(value) {
  if (!value) {
    return '';
  }

  return value.endsWith('/') ? value.slice(0, -1) : value;
}

function renderCatalog(checks) {
  catalogGrid.replaceChildren();

  if (!checks.length) {
    catalogGrid.className = 'catalog-grid empty-state';
    catalogGrid.textContent = 'No public check catalog is available.';
    return;
  }

  catalogGrid.className = 'catalog-grid';

  for (const check of checks.sort((left, right) => right.confidence - left.confidence)) {
    const node = catalogTemplate.content.cloneNode(true);
    node.querySelector('.catalog-label').textContent = check.label;
    node.querySelector('.catalog-severity').textContent = humanize(check.severity);
    node.querySelector('.catalog-family').textContent = check.family;
    node.querySelector('.catalog-confidence').textContent = `${check.confidence}% confidence`;
    node.querySelector('.catalog-description').textContent = check.description;
    node.querySelector('.catalog-rationale').textContent = check.rationale;
    catalogGrid.append(node);
  }
}