import { jsPDF } from 'jspdf';
import type {
  AnalyzedApplication,
  DeviceRecord,
  MonitoringSession,
  NetworkConnection,
  PrivacyPolicyAnalysis,
  RiskAlert,
  ThirdPartyService,
} from '../types/nla';

export async function computeSha256Hex(content: string): Promise<string> {
  const bytes = new TextEncoder().encode(content);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function triggerBrowserDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export interface EvidencePackage {
  generatedAt: string;
  platform: 'NLA — Network & Location Awareness';
  developer: 'Newtonix Tech House';
  session: MonitoringSession;
  device: DeviceRecord | null;
  applications: AnalyzedApplication[];
  connections: NetworkConnection[];
  thirdParties: ThirdPartyService[];
  policies: PrivacyPolicyAnalysis[];
  riskAlerts: RiskAlert[];
}

export async function generateAndDownloadForensicExport(
  pkg: EvidencePackage,
  format: 'json' | 'csv' | 'html' | 'pdf'
): Promise<{ sha256: string; recordCount: number; filename: string }> {
  const canonicalJson = JSON.stringify(pkg, null, 2);
  const sha256 = await computeSha256Hex(canonicalJson);
  const recordCount =
    pkg.connections.length +
    pkg.applications.length +
    pkg.thirdParties.length +
    pkg.riskAlerts.length +
    pkg.policies.length;
  const baseName = `nla-forensic-${pkg.session.id.slice(0, 16)}`;

  if (format === 'json') {
    const payload = JSON.stringify({ ...pkg, integritySha256: sha256 }, null, 2);
    triggerBrowserDownload(new Blob([payload], { type: 'application/json' }), `${baseName}.json`);
    return { sha256, recordCount, filename: `${baseName}.json` };
  }

  if (format === 'csv') {
    const headers = [
      'ObservedAt',
      'Application',
      'DestinationDomain',
      'DestinationIP',
      'Port',
      'Protocol',
      'City',
      'Country',
      'ASN',
      'HostingOrg',
      'Company',
      'Category',
      'PartyType',
      'Bytes',
      'Requests',
      'Background',
      'Confidence',
      'EvidenceType',
      'EvidenceSummary',
    ];
    const escape = (val: unknown) => `"${String(val ?? '').replace(/"/g, '""')}"`;
    const rows = pkg.connections.map((c) =>
      [
        c.observedAt,
        c.appName,
        c.destinationDomain,
        c.destinationIp,
        c.destinationPort,
        c.protocol,
        c.city,
        c.country,
        c.asn,
        c.hostingOrg,
        c.companyName,
        c.serviceCategory,
        c.partyType,
        c.bytesTransferred,
        c.requestCount,
        c.isBackground,
        c.confidence,
        c.evidenceType,
        c.evidenceSummary,
      ]
        .map(escape)
        .join(',')
    );
    const csv = [
      `# NLA Forensic Export | Newtonix Tech House | Session: ${pkg.session.id} | Integrity SHA-256: ${sha256}`,
      headers.join(','),
      ...rows,
    ].join('\n');
    triggerBrowserDownload(new Blob([csv], { type: 'text/csv;charset=utf-8' }), `${baseName}.csv`);
    return { sha256, recordCount, filename: `${baseName}.csv` };
  }

  if (format === 'html') {
    const connRows = pkg.connections
      .map(
        (c) => `<tr>
          <td>${c.observedAt}</td>
          <td>${c.appName}</td>
          <td>${c.destinationDomain}</td>
          <td>${c.destinationIp}</td>
          <td>${c.city}, ${c.country}</td>
          <td>${c.asn} · ${c.hostingOrg}</td>
          <td>${c.serviceCategory} (${c.partyType})</td>
          <td>${c.confidence}</td>
        </tr>`
      )
      .join('');
    const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>NLA Forensic Report — ${pkg.session.title}</title>
<style>
  body { font-family: system-ui, sans-serif; background: #070E1C; color: #E2E8F0; padding: 32px; }
  h1, h2 { color: #38BDF8; }
  .meta { font-family: monospace; font-size: 12px; background: #0F172A; padding: 16px; border-radius: 8px; border: 1px solid #1E293B; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 12px; }
  th, td { border: 1px solid #1E293B; padding: 8px; text-align: left; }
  th { background: #0F172A; color: #94A3B8; }
</style>
</head>
<body>
  <h1>NLA — Digital Privacy Forensic Report</h1>
  <p>Developed by Newtonix Tech House · See Your Data. Know Its Destination. Control Your Digital Privacy.</p>
  <div class="meta">
    <div>Session ID: ${pkg.session.id}</div>
    <div>Device: ${pkg.device?.name || pkg.session.deviceId} (${pkg.device?.platform || 'unknown'})</div>
    <div>Generated At: ${pkg.generatedAt}</div>
    <div>Integrity SHA-256: ${sha256}</div>
  </div>
  <h2>Observed Network Transmissions (${pkg.connections.length})</h2>
  <table>
    <thead><tr><th>Timestamp</th><th>Application</th><th>Domain</th><th>IP</th><th>Approx. Server Location</th><th>ASN / Hosting</th><th>Classification</th><th>Confidence</th></tr></thead>
    <tbody>${connRows || '<tr><td colspan="8">No network connections recorded in this session.</td></tr>'}</tbody>
  </table>
</body>
</html>`;
    triggerBrowserDownload(new Blob([html], { type: 'text/html;charset=utf-8' }), `${baseName}.html`);
    return { sha256, recordCount, filename: `${baseName}.html` };
  }

  // Real binary PDF generation via jsPDF
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  let y = 44;
  doc.setFontSize(16);
  doc.text('NLA — Digital Privacy Forensic Evidence Report', 40, y);
  y += 18;
  doc.setFontSize(9);
  doc.text('Newtonix Tech House · Network & Location Awareness', 40, y);
  y += 20;
  doc.text(`Session ID: ${pkg.session.id}`, 40, y);
  y += 13;
  doc.text(`Device: ${pkg.device?.name || pkg.session.deviceId} (${pkg.device?.platform || 'unknown'})`, 40, y);
  y += 13;
  doc.text(`Generated: ${pkg.generatedAt}`, 40, y);
  y += 13;
  doc.text(`SHA-256: ${sha256}`, 40, y);
  y += 22;

  doc.setFontSize(11);
  doc.text(`Observed Connections (${pkg.connections.length}) | Risk Alerts (${pkg.riskAlerts.length}) | Apps (${pkg.applications.length})`, 40, y);
  y += 16;
  doc.setFontSize(8);

  for (const conn of pkg.connections.slice(0, 35)) {
    if (y > 760) {
      doc.addPage();
      y = 44;
    }
    const line = `${conn.observedAt.slice(0, 19)} | ${conn.appName} -> ${conn.destinationDomain} (${conn.destinationIp}) | ${conn.city}, ${conn.country} | ${conn.serviceCategory} [${conn.confidence}]`;
    doc.text(line.slice(0, 108), 40, y);
    y += 12;
  }

  if (pkg.riskAlerts.length > 0) {
    y += 12;
    if (y > 740) {
      doc.addPage();
      y = 44;
    }
    doc.setFontSize(11);
    doc.text('Risk & Threat Findings', 40, y);
    y += 14;
    doc.setFontSize(8);
    for (const alert of pkg.riskAlerts.slice(0, 20)) {
      if (y > 760) {
        doc.addPage();
        y = 44;
      }
      doc.text(`[${alert.severity.toUpperCase()}] ${alert.title} (${alert.appName}) - ${alert.status}`.slice(0, 108), 40, y);
      y += 12;
    }
  }

  doc.save(`${baseName}.pdf`);
  return { sha256, recordCount, filename: `${baseName}.pdf` };
}
