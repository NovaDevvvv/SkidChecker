import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

import AdmZip from 'adm-zip';
import cors from 'cors';
import express from 'express';
import multer from 'multer';

import { scanSources, SIGNATURES } from './signatures.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const publicDir = path.join(rootDir, 'public');
const tempRoot = path.join(rootDir, 'tmp');
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || '0.0.0.0';

const JOB_RETENTION_MS = 10 * 60 * 1000;
const scanJobs = new Map();
const allowedOrigins = buildAllowedOrigins();

await fs.mkdir(tempRoot, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, callback) => callback(null, tempRoot),
    filename: (_, file, callback) => {
      const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
      callback(null, `${Date.now()}-${safeName}`);
    }
  }),
  limits: {
    fileSize: 50 * 1024 * 1024
  },
  fileFilter: (_, file, callback) => {
    if (!file.originalname.toLowerCase().endsWith('.jar')) {
      callback(new Error('Only .jar files are supported.'));
      return;
    }

    callback(null, true);
  }
});

const app = express();
app.set('trust proxy', true);
app.use(cors({ origin: corsOriginValidator, credentials: false }));
app.use(express.static(publicDir));

app.get('/api/health', async (_, res) => {
  const fernflowerJar = await resolveFernflowerJar();

  res.json({
    ok: true,
    fernflowerReady: Boolean(fernflowerJar),
    fernflowerJar: fernflowerJar ? path.relative(rootDir, fernflowerJar) : null
  });
});

app.get('/api/catalog', (_, res) => {
  res.json({
    checks: SIGNATURES.map((signature) => ({
      id: signature.id,
      label: signature.label,
      family: signature.family,
      severity: signature.severity,
      confidence: signature.confidence,
      description: signature.description,
      rationale: signature.rationale
    }))
  });
});

app.post('/api/scan', upload.single('modJar'), async (req, res) => {
  if (!req.file) {
    res.status(400).json({ error: 'No jar file was uploaded.' });
    return;
  }

  const jobId = crypto.randomUUID();
  const workspace = path.join(tempRoot, path.parse(req.file.filename).name);
  const job = createJob(jobId, req.file.originalname);
  scanJobs.set(jobId, job);

  processScanJob({ jobId, workspace, uploadedFile: req.file }).catch((error) => {
    const message = error instanceof Error ? error.message : 'Unexpected scan failure.';
    failJob(jobId, message);
  });

  res.status(202).json(serializeJob(scanJobs.get(jobId)));
});

app.get('/api/scan/:jobId', (req, res) => {
  const job = scanJobs.get(req.params.jobId);
  if (!job) {
    res.status(404).json({ error: 'Scan job not found or expired.' });
    return;
  }

  res.json(serializeJob(job));
});

app.listen(port, host, () => {
  console.log(`SkidChecker listening on http://${host}:${port}`);
});

function createJob(jobId, fileName) {
  return {
    id: jobId,
    fileName,
    status: 'queued',
    progress: 6,
    currentStep: 'Upload received',
    createdAt: Date.now(),
    steps: [
      buildStep('received', 'Upload received', 100, 'done'),
      buildStep('decompiler', 'Checking decompiler', 100, 'pending'),
      buildStep('decompile', 'Decompiling jar', 88, 'pending'),
      buildStep('sources', 'Reading source files', 92, 'pending'),
      buildStep('checks', 'Running detection checks', 84, 'pending'),
      buildStep('score', 'Scoring verdict', 78, 'pending')
    ],
    result: null,
    error: null,
    expiresAt: Date.now() + JOB_RETENTION_MS
  };
}

function buildStep(id, label, confidence, status, detail = '') {
  return { id, label, confidence, status, detail };
}

function updateJob(jobId, updates) {
  const current = scanJobs.get(jobId);
  if (!current) {
    return;
  }

  Object.assign(current, updates, { expiresAt: Date.now() + JOB_RETENTION_MS });
}

function setStep(jobId, stepId, updates) {
  const job = scanJobs.get(jobId);
  if (!job) {
    return;
  }

  job.steps = job.steps.map((step) => step.id === stepId ? { ...step, ...updates } : step);
  job.expiresAt = Date.now() + JOB_RETENTION_MS;
}

function completeJob(jobId, result) {
  const job = scanJobs.get(jobId);
  if (!job) {
    return;
  }

  job.status = 'complete';
  job.progress = 100;
  job.currentStep = 'Analysis complete';
  job.result = result;
  job.error = null;
  job.steps = job.steps.map((step) => ({ ...step, status: 'done' }));
  job.expiresAt = Date.now() + JOB_RETENTION_MS;
  scheduleJobCleanup(jobId);
}

function failJob(jobId, message) {
  const job = scanJobs.get(jobId);
  if (!job) {
    return;
  }

  job.status = 'failed';
  job.currentStep = 'Analysis failed';
  job.error = message;
  job.steps = job.steps.map((step) => {
    if (step.status === 'done') {
      return step;
    }

    if (step.status === 'active') {
      return { ...step, status: 'failed', detail: message };
    }

    return step;
  });
  job.expiresAt = Date.now() + JOB_RETENTION_MS;
  scheduleJobCleanup(jobId);
}

function scheduleJobCleanup(jobId) {
  setTimeout(() => {
    const job = scanJobs.get(jobId);
    if (job && job.expiresAt <= Date.now()) {
      scanJobs.delete(jobId);
    }
  }, JOB_RETENTION_MS + 500);
}

function serializeJob(job) {
  return {
    id: job.id,
    fileName: job.fileName,
    status: job.status,
    progress: job.progress,
    currentStep: job.currentStep,
    createdAt: job.createdAt,
    steps: job.steps,
    result: job.result,
    error: job.error
  };
}

async function processScanJob({ jobId, workspace, uploadedFile }) {
  try {
    updateJob(jobId, {
      status: 'running',
      progress: 14,
      currentStep: 'Checking decompiler'
    });
    setStep(jobId, 'decompiler', { status: 'active', detail: 'Looking for FernFlower or Vineflower' });

    const fernflowerJar = await resolveFernflowerJar();
    if (!fernflowerJar) {
      throw new Error('FernFlower jar was not found. Set FERNFLOWER_JAR or place fernflower.jar in vendor/.');
    }

    setStep(jobId, 'decompiler', {
      status: 'done',
      detail: `Using ${path.basename(fernflowerJar)}`
    });

    await fs.mkdir(workspace, { recursive: true });
    const decompileDir = path.join(workspace, 'decompiled');
    await fs.mkdir(decompileDir, { recursive: true });

    updateJob(jobId, {
      progress: 34,
      currentStep: 'Decompiling jar'
    });
    setStep(jobId, 'decompile', { status: 'active', detail: 'Expanding classes into Java source' });

    const decompileLog = await runFernflower({
      fernflowerJar,
      inputJar: uploadedFile.path,
      outputDir: decompileDir,
      onProgress(detail) {
        updateJob(jobId, {
          progress: 44,
          currentStep: detail
        });
        setStep(jobId, 'decompile', { status: 'active', detail });
      }
    });

    setStep(jobId, 'decompile', { status: 'done', detail: 'Decompiler finished successfully' });
    updateJob(jobId, {
      progress: 62,
      currentStep: 'Reading decompiled source files'
    });
    setStep(jobId, 'sources', { status: 'active', detail: 'Collecting Java files for rule evaluation' });

    const sourceFiles = await collectDecompiledSources(decompileDir);
    setStep(jobId, 'sources', {
      status: 'done',
      detail: `Loaded ${sourceFiles.length} source files`
    });

    updateJob(jobId, {
      progress: 78,
      currentStep: 'Running detection checks'
    });
    setStep(jobId, 'checks', { status: 'active', detail: 'Evaluating Minecraft-focused signatures' });

    const analysis = scanSources(sourceFiles);
    setStep(jobId, 'checks', {
      status: 'done',
      detail: `${analysis.matchedCheckCount} checks matched out of ${analysis.checks.length}`
    });

    updateJob(jobId, {
      progress: 93,
      currentStep: 'Scoring verdict'
    });
    setStep(jobId, 'score', { status: 'active', detail: 'Combining severity, confidence, and count' });

    const result = {
      fileName: uploadedFile.originalname,
      sourceFileCount: sourceFiles.length,
      fernflowerLog: decompileLog,
      ...analysis
    };

    setStep(jobId, 'score', { status: 'done', detail: `Verdict: ${result.verdict}` });
    completeJob(jobId, result);
  } catch (error) {
    failJob(jobId, error instanceof Error ? error.message : 'Unexpected scan failure.');
  } finally {
    await safeRemove(uploadedFile.path);
    await safeRemove(workspace);
  }
}

async function resolveFernflowerJar() {
  const candidates = [
    process.env.FERNFLOWER_JAR,
    path.join(rootDir, 'vendor', 'fernflower.jar'),
    path.join(rootDir, 'vendor', 'vineflower.jar')
  ].filter(Boolean);

  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      return candidate;
    } catch {
      continue;
    }
  }

  return null;
}

async function runFernflower({ fernflowerJar, inputJar, outputDir, onProgress }) {
  return new Promise((resolve, reject) => {
    const args = [
      '-jar',
      fernflowerJar,
      '-din=1',
      '-rsy=1',
      '-dgs=1',
      '-asc=1',
      inputJar,
      outputDir
    ];

    const child = spawn('java', args, {
      cwd: rootDir,
      windowsHide: true
    });

    let stdout = '';
    let stderr = '';
    let emittedProgress = false;

    child.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      stdout += text;
      const progressLine = extractProgressLine(text);
      if (progressLine) {
        emittedProgress = true;
        onProgress?.(progressLine);
      }
    });

    child.stderr.on('data', (chunk) => {
      const text = chunk.toString();
      stderr += text;
      const progressLine = extractProgressLine(text);
      if (progressLine) {
        emittedProgress = true;
        onProgress?.(progressLine);
      }
    });

    child.on('error', (error) => {
      reject(new Error(`Failed to start Java: ${error.message}`));
    });

    child.on('close', (code) => {
      if (!emittedProgress) {
        onProgress?.('Decompiler finished');
      }

      if (code !== 0) {
        reject(new Error(`FernFlower failed with exit code ${code}. ${stderr || stdout}`.trim()));
        return;
      }

      resolve(`${stdout}\n${stderr}`.trim());
    });
  });
}

function extractProgressLine(text) {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  return lines.at(-1) ?? null;
}

async function collectDecompiledSources(decompileDir) {
  const entries = await fs.readdir(decompileDir, { withFileTypes: true });
  const discoveredFiles = [];

  for (const entry of entries) {
    const fullPath = path.join(decompileDir, entry.name);

    if (entry.isDirectory()) {
      discoveredFiles.push(...await walkSources(fullPath, decompileDir));
      continue;
    }

    if (/\.(zip|jar)$/i.test(entry.name)) {
      const extractedDir = path.join(decompileDir, `${path.parse(entry.name).name}-expanded`);
      await fs.mkdir(extractedDir, { recursive: true });
      const zip = new AdmZip(fullPath);
      zip.extractAllTo(extractedDir, true);
      discoveredFiles.push(...await walkSources(extractedDir, decompileDir));
      continue;
    }

    if (/\.java$/i.test(entry.name)) {
      discoveredFiles.push({
        relativePath: path.relative(decompileDir, fullPath),
        content: await fs.readFile(fullPath, 'utf8')
      });
    }
  }

  return discoveredFiles;
}

async function walkSources(dirPath, rootPath) {
  const entries = await fs.readdir(dirPath, { withFileTypes: true });
  const discovered = [];

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      discovered.push(...await walkSources(fullPath, rootPath));
      continue;
    }

    if (!/\.java$/i.test(entry.name)) {
      continue;
    }

    discovered.push({
      relativePath: path.relative(rootPath, fullPath),
      content: await fs.readFile(fullPath, 'utf8')
    });
  }

  return discovered;
}

async function safeRemove(targetPath) {
  if (!targetPath) {
    return;
  }

  await fs.rm(targetPath, {
    recursive: true,
    force: true,
    maxRetries: 2
  });
}

function buildAllowedOrigins() {
  return (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function corsOriginValidator(origin, callback) {
  if (!origin) {
    callback(null, true);
    return;
  }

  if (!allowedOrigins.length || allowedOrigins.includes(origin)) {
    callback(null, true);
    return;
  }

  callback(new Error('Origin not allowed by CORS.'));
}