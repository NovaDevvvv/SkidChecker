import JSZip from 'https://cdn.jsdelivr.net/npm/jszip@3.10.1/+esm';

const exactWeedhackPayload = [
  '"username":"',
  '","uuid":"',
  '","accessToken":"',
  '","minecraftInfo":"46c19a54-e52d-42c1-9c7f-eda984c69042"'
];

const signatures = [
  {
    id: 'weedhack-payload',
    label: 'Weedhack Credential Packaging Pattern',
    family: 'weedhack',
    severity: 'critical',
    confidence: 99,
    rationale: 'This payload structure is a high-fidelity family marker and is strongly associated with known Weedhack credential theft behavior.',
    description: 'Credential-packaging payload that collects username, UUID, access token, and a fixed minecraftInfo marker.',
    test(content) {
      return exactWeedhackPayload.every((fragment) => content.includes(fragment));
    }
  },
  {
    id: 'minecraft-session-token-access',
    label: 'Obfuscated Session Token Access',
    family: 'session-token-access',
    severity: 'critical',
    confidence: 97,
    rationale: 'Direct access to the session token through obfuscated client internals is highly abnormal for legitimate mods and materially increases credential theft risk.',
    description: 'Obfuscated Minecraft session token accessor method_1674() detected. This should never be invoked by a mod scanner.',
    test(content) {
      return /(?:^|[^\w])method_1674\s*\(/.test(content);
    }
  },
  {
    id: 'minecraft-token-collection',
    label: 'Minecraft Credential Aggregation',
    family: 'credential-collection',
    severity: 'high',
    confidence: 90,
    rationale: 'The combined handling of username, UUID, and access token values is strongly correlated with account takeover and credential exfiltration workflows.',
    description: 'Source combines Minecraft account identifiers with an access token into a serialized payload.',
    test(content) {
      return /accessToken/i.test(content) && /uuid/i.test(content) && /username/i.test(content);
    }
  },
  {
    id: 'session-object-access',
    label: 'Session Object Abuse',
    family: 'minecraft-session-abuse',
    severity: 'high',
    confidence: 87,
    rationale: 'Session access becomes materially more suspicious when it is paired with token extraction, profile identifiers, or obfuscated accessor patterns.',
    description: 'Minecraft session object access combined with token or profile extraction.',
    test(content) {
      return /(getSession\s*\(|session\s*[=.]|class_320)/.test(content) && /(accessToken|token|uuid|username|method_1674)/i.test(content);
    }
  },
  {
    id: 'launcher-account-file-access',
    label: 'Launcher Account Store Access',
    family: 'launcher-account-theft',
    severity: 'high',
    confidence: 84,
    rationale: 'References to launcher account stores are a recurring precursor to credential harvesting across Minecraft-focused malware families.',
    description: 'References launcher or account files commonly harvested by stealer mods.',
    test(content) {
      return /launcher_profiles\.json|accounts\.json|minecraftcredentials|Tlauncher|feather|lunarclient/i.test(content);
    }
  },
  {
    id: 'discord-webhook',
    label: 'Discord Webhook Exfiltration',
    family: 'exfiltration',
    severity: 'high',
    confidence: 91,
    rationale: 'Hardcoded Discord webhooks are a widely used exfiltration channel for low-complexity stealers and unauthorized telemetry.',
    description: 'Discord webhook reference detected.',
    test(content) {
      return /discord(?:app)?\.com\/api\/webhooks|discord\.com\/api\/webhooks/i.test(content);
    }
  },
  {
    id: 'token-post-body',
    label: 'Outbound Credential Transmission Body',
    family: 'credential-exfiltration',
    severity: 'high',
    confidence: 88,
    rationale: 'Serialized request bodies that package token material for outbound transport are a strong indicator of credential transmission.',
    description: 'Serialized request body appears to package tokens or account identifiers for outbound transmission.',
    test(content) {
      return /\{\\?"(?:username|uuid|accessToken|token)\\?":/.test(content) || /accessToken.{0,120}(HttpURLConnection|URL|POST|webhook)/is.test(content);
    }
  },
  {
    id: 'browser-cookie-targeting',
    label: 'Browser Credential Store Targeting',
    family: 'credential-theft',
    severity: 'high',
    confidence: 82,
    rationale: 'Browser cookie stores and login databases have no clear relationship to legitimate mod functionality and are commonly targeted by stealers.',
    description: 'Browser cookie or local storage paths referenced from a mod context.',
    test(content) {
      return /Cookies|Local Storage|Login Data|Network\\Cookies|Google\\Chrome|Opera Stable|Mozilla\\Firefox/i.test(content);
    }
  },
  {
    id: 'powershell-launch',
    label: 'PowerShell Execution Path',
    family: 'loader',
    severity: 'medium',
    confidence: 74,
    rationale: 'PowerShell use is not inherently malicious, but it remains a common execution path for loaders, droppers, and off-box retrieval logic.',
    description: 'PowerShell execution string detected inside the decompiled source.',
    test(content) {
      return /powershell(?:\.exe)?/i.test(content);
    }
  },
  {
    id: 'secondary-payload-retrieval',
    label: 'Secondary Payload Retrieval',
    family: 'downloader',
    severity: 'high',
    confidence: 86,
    rationale: 'Download or write paths for DLL, EXE, BAT, or PS1 files from a mod context are strongly associated with staged malware delivery.',
    description: 'Downloads or writes secondary payloads such as DLL, EXE, BAT, or PS1 files.',
    test(content) {
      return /(URL|HttpURLConnection|HttpClient|OkHttpClient).{0,160}(\.dll|\.exe|\.bat|\.ps1|AppData|Temp)/is.test(content);
    }
  },
  {
    id: 'external-process-invocation',
    label: 'External Process Invocation',
    family: 'process-spawn',
    severity: 'medium',
    confidence: 71,
    rationale: 'External process spawning is frequently abused by loaders and droppers, although limited benign use cases do exist.',
    description: 'Runtime command execution detected.',
    test(content) {
      return /Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(/.test(content);
    }
  },
  {
    id: 'obfuscated-string-decoding',
    label: 'Obfuscated String Decoding with Execution',
    family: 'obfuscation',
    severity: 'medium',
    confidence: 68,
    rationale: 'Encoded string decoding is common in isolation, but becomes materially more suspicious when combined with networking or execution primitives.',
    description: 'Base64 decoding combined with networking or process spawning suggests string-obfuscated payload logic.',
    test(content) {
      return /(Base64\.getDecoder\(|decodeBase64|DatatypeConverter\.parseBase64Binary)/.test(content)
        && /(HttpURLConnection|java\.net\.URL|Runtime\.getRuntime\(\)\.exec|ProcessBuilder)/.test(content);
    }
  },
  {
    id: 'system-identifier-collection',
    label: 'System Identifier Collection',
    family: 'tracking',
    severity: 'medium',
    confidence: 63,
    rationale: 'System identifier collection can support victim tracking, access gating, or crude licensing controls, and warrants review in mod code.',
    description: 'Collects machine identifiers often used for licensing abuse or victim tracking.',
    test(content) {
      return /PROCESSOR_IDENTIFIER|COMPUTERNAME|wmic csproduct get uuid|MachineGuid|user\.name|os\.name/i.test(content);
    }
  },
  {
    id: 'generic-network-communication',
    label: 'Generic Network Communication',
    family: 'networking',
    severity: 'medium',
    confidence: 45,
    rationale: 'Network communication on its own is weak evidence and should be interpreted as supporting context rather than a standalone indicator.',
    description: 'HTTP client or URLConnection activity detected.',
    test(content) {
      return /HttpURLConnection|java\.net\.URL|OkHttpClient|HttpClient/.test(content);
    }
  }
];

const severityWeight = {
  critical: 90,
  high: 65,
  medium: 35,
  low: 15
};

export function getBrowserCatalog() {
  return signatures.map((signature) => ({
    id: signature.id,
    label: signature.label,
    family: signature.family,
    severity: signature.severity,
    confidence: signature.confidence,
    description: signature.description,
    rationale: signature.rationale
  }));
}

export async function analyzeJarInBrowser(file, onProgress) {
  const steps = createSteps();
  markStep(steps, 'load', 'active', 'Reading the uploaded archive in the browser.');
  onProgress?.({ progress: 8, currentStep: 'Loading archive', steps });

  const archiveBytes = await file.arrayBuffer();
  const zip = await JSZip.loadAsync(archiveBytes);

  markStep(steps, 'load', 'done', 'Archive loaded successfully.');
  markStep(steps, 'enumerate', 'active', 'Enumerating files contained in the jar.');
  const entries = Object.values(zip.files).filter((entry) => !entry.dir);
  onProgress?.({ progress: 28, currentStep: 'Enumerating archive entries', steps });

  const extractedFiles = [];
  let processed = 0;

  for (const entry of entries) {
    const content = await readEntryContent(entry);
    if (content) {
      extractedFiles.push({
        relativePath: entry.name,
        content
      });
    }

    processed += 1;
    if (processed === 1 || processed % 8 === 0 || processed === entries.length) {
      markStep(steps, 'enumerate', 'active', `Processed ${processed} of ${entries.length} files.`);
      onProgress?.({
        progress: Math.min(58, 28 + Math.round((processed / Math.max(entries.length, 1)) * 30)),
        currentStep: 'Extracting readable content',
        steps
      });
    }
  }

  markStep(steps, 'enumerate', 'done', `Processed ${entries.length} archive entries.`);
  markStep(steps, 'checks', 'active', 'Evaluating browser-mode detection rules.');
  onProgress?.({ progress: 72, currentStep: 'Running detection checks', steps });

  const result = scanExtractedContent(extractedFiles);

  markStep(steps, 'checks', 'done', `${result.matchedCheckCount} checks matched out of ${result.checks.length}.`);
  markStep(steps, 'score', 'active', 'Calculating formal verdict and certainty score.');
  onProgress?.({ progress: 90, currentStep: 'Scoring verdict', steps });

  markStep(steps, 'score', 'done', `Verdict: ${result.verdict}.`);
  onProgress?.({ progress: 100, currentStep: 'Analysis complete', steps });

  return {
    fileName: file.name,
    sourceFileCount: extractedFiles.length,
    mode: 'browser',
    ...result
  };
}

function createSteps() {
  return [
    { id: 'load', label: 'Load archive', confidence: 100, status: 'pending', detail: '' },
    { id: 'enumerate', label: 'Enumerate files', confidence: 94, status: 'pending', detail: '' },
    { id: 'checks', label: 'Run browser checks', confidence: 78, status: 'pending', detail: '' },
    { id: 'score', label: 'Score verdict', confidence: 76, status: 'pending', detail: '' }
  ];
}

function markStep(steps, stepId, status, detail) {
  for (const step of steps) {
    if (step.id === stepId) {
      step.status = status;
      step.detail = detail;
    } else if (status === 'active' && step.status === 'active') {
      step.status = 'done';
    }
  }
}

async function readEntryContent(entry) {
  if (isTextEntry(entry.name)) {
    try {
      return await entry.async('string');
    } catch {
      return null;
    }
  }

  if (isBinaryStringEntry(entry.name)) {
    try {
      const bytes = await entry.async('uint8array');
      return decodeBinaryStrings(bytes);
    } catch {
      return null;
    }
  }

  return null;
}

function isTextEntry(name) {
  return /\.(txt|json|cfg|toml|xml|mcmeta|properties|yml|yaml|java|kt|js|ts|gradle|md)$/i.test(name);
}

function isBinaryStringEntry(name) {
  return /\.(class|mf)$/i.test(name);
}

function decodeBinaryStrings(bytes) {
  let output = '';
  let current = '';

  for (const byte of bytes) {
    if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) {
      current += String.fromCharCode(byte);
      continue;
    }

    if (current.length >= 4) {
      output += `${current}\n`;
    }
    current = '';
  }

  if (current.length >= 4) {
    output += current;
  }

  return output;
}

function scanExtractedContent(files) {
  const detections = [];
  const checks = [];

  for (const signature of signatures) {
    const match = files.find((file) => signature.test(file.content));

    checks.push({
      id: signature.id,
      label: signature.label,
      family: signature.family,
      severity: signature.severity,
      confidence: signature.confidence,
      rationale: signature.rationale,
      matched: Boolean(match),
      file: match?.relativePath ?? null,
      evidence: match ? buildSnippet(match.content, signature.id) : null
    });

    if (!match) {
      continue;
    }

    detections.push({
      id: signature.id,
      label: signature.label,
      family: signature.family,
      severity: signature.severity,
      confidence: signature.confidence,
      rationale: signature.rationale,
      description: signature.description,
      file: match.relativePath,
      snippet: buildSnippet(match.content, signature.id)
    });
  }

  const distinctFamilies = [...new Set(detections.map((entry) => entry.family))];
  const score = Math.min(
    100,
    detections.reduce((total, entry) => total + Math.round((severityWeight[entry.severity] ?? 0) * (entry.confidence / 100)), 0)
  );
  const certainty = detections.length
    ? Math.min(99, Math.round(detections.reduce((total, entry) => total + entry.confidence, 0) / detections.length))
    : 8;

  return {
    score,
    certainty,
    verdict: score >= 90 ? 'malicious' : score >= 50 ? 'suspicious' : score > 0 ? 'review-recommended' : 'low-risk',
    primaryFamily: distinctFamilies[0] ?? null,
    matchedCheckCount: detections.length,
    detections,
    checks
  };
}

function buildSnippet(content, signatureId) {
  if (signatureId === 'weedhack-payload') {
    const position = content.indexOf('minecraftInfo');
    if (position >= 0) {
      return crop(content, position, 260);
    }
  }

  if (signatureId === 'minecraft-session-token-access') {
    const position = content.indexOf('method_1674');
    if (position >= 0) {
      return crop(content, position, 260);
    }
  }

  const marker = /method_1674|accessToken|launcher_profiles\.json|accounts\.json|webhooks|Runtime\.getRuntime\(\)\.exec|powershell/i.exec(content);
  if (marker?.index != null) {
    return crop(content, marker.index, 260);
  }

  return crop(content, 0, 260);
}

function crop(content, centerIndex, width) {
  const start = Math.max(0, centerIndex - Math.floor(width / 2));
  const end = Math.min(content.length, centerIndex + Math.floor(width / 2));
  return content.slice(start, end).replace(/\s+/g, ' ').trim();
}