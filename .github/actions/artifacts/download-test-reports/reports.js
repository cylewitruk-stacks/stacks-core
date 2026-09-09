const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

/** Write matching, unexpired artifacts from every REST page to a manifest. */
async function listReports(github, context, kind, manifest) {
  if (!['codecov', 'junit'].includes(kind)) throw new Error(`Unsupported report kind: ${kind}`);
  fs.writeFileSync(manifest, '');
  for (let page = 1; ; page++) {
    const { data } = await github.rest.actions.listWorkflowRunArtifacts({
      ...context.repo, run_id: context.runId, per_page: 100, page,
    });
    if (data.artifacts.length === 0) break;
    const reports = data.artifacts.filter(artifact =>
      !artifact.expired && artifact.name.startsWith(`${kind}-`));
    for (const report of reports) {
      fs.appendFileSync(manifest, `${JSON.stringify(report)}\n`);
    }
  }
  const latest = new Map();
  for (const line of fs.readFileSync(manifest, 'utf8').split('\n').filter(Boolean)) {
    const report = JSON.parse(line);
    if (!latest.has(report.name) || latest.get(report.name).id < report.id) {
      latest.set(report.name, report);
    }
  }
  const reports = [...latest.values()];
  if (reports.length === 0) throw new Error(`No available ${kind} reports`);
  return reports;
}

/** Download one selected artifact by ID and extract its nonempty report file. */
async function downloadReport(github, context, kind, report, destination, temporary) {
  const suffix = report.name.slice(kind.length + 1);
  if (!/^[A-Za-z0-9_.-]+$/.test(suffix)) throw new Error(`Invalid report name: ${report.name}`);
  const file = kind === 'codecov' ? `lcov_${suffix}.info` : `junit_${suffix}.xml`;
  const { data } = await github.rest.actions.downloadArtifact({
    ...context.repo, artifact_id: report.id, archive_format: 'zip',
  });
  const archive = Buffer.from(data);
  if (report.digest) {
    const digest = `sha256:${crypto.createHash('sha256').update(archive).digest('hex')}`;
    if (digest !== report.digest) throw new Error(`Digest mismatch: ${report.name}`);
  }
  const zip = path.join(temporary, `${report.id}.zip`);
  fs.writeFileSync(zip, archive);
  const output = fs.openSync(path.join(destination, file), 'wx');
  try {
    // Extract only the expected report, without trusting archive paths.
    execFileSync('unzip', ['-p', zip, file], { stdio: ['ignore', output, 'pipe'] });
    if (fs.fstatSync(output).size === 0) throw new Error(`Empty report: ${report.name}`);
  } finally {
    fs.closeSync(output);
    fs.unlinkSync(zip);
  }
}

/** Finish listing before downloading the selected reports, five at a time. */
async function collect({ github, core, context }, kind, destination) {
  const temporary = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP, 'test-reports-'));
  try {
    const reports = await listReports(github, context, kind, path.join(temporary, 'manifest.jsonl'));
    core.info(`Downloading ${reports.length} available ${kind} reports`);
    fs.mkdirSync(destination, { recursive: true });
    for (let index = 0; index < reports.length; index += 5) {
      const results = await Promise.allSettled(reports.slice(index, index + 5).map(report =>
        downloadReport(github, context, kind, report, destination, temporary)));
      const failure = results.find(result => result.status === 'rejected');
      if (failure) throw failure.reason;
    }
    core.info(`Downloaded ${reports.length} reports`);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

module.exports = { listReports, downloadReport, collect };
