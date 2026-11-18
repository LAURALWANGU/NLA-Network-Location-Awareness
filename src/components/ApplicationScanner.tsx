import React, { useState } from 'react';
import { AppWindow, FileCode2, Globe, Info, Shield, Trash2 } from 'lucide-react';
import { useNla } from '../context/NlaContext';
import type { AnalyzedApplication, PlatformType } from '../types/nla';

const SENSITIVE_GROUPS = [
  { label: 'Camera', keys: ['CAMERA'] },
  { label: 'Microphone', keys: ['RECORD_AUDIO', 'MICROPHONE'] },
  { label: 'Location', keys: ['LOCATION', 'GEOLOCATION'] },
  { label: 'Contacts', keys: ['CONTACTS'] },
  { label: 'Photos & Files', keys: ['STORAGE', 'MEDIA', 'PHOTOS', 'COOKIE'] },
  { label: 'Bluetooth', keys: ['BLUETOOTH'] },
  { label: 'Background', keys: ['BACKGROUND', 'BOOT', 'FOREGROUND_SERVICE'] },
];

export function ApplicationScanner() {
  const { applications, scanWebAppAndSave, scanManifestAndSave, deleteRecord } = useNla();
  const [scanMode, setScanMode] = useState<'web' | 'manifest'>('web');
  const [webUrl, setWebUrl] = useState('');
  const [appName, setAppName] = useState('');
  const [packageId, setPackageId] = useState('');
  const [developer, setDeveloper] = useState('');
  const [version, setVersion] = useState('1.0.0');
  const [platform, setPlatform] = useState<PlatformType>('android');
  const [policyUrl, setPolicyUrl] = useState('');
  const [manifestContent, setManifestContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedApp, setSelectedApp] = useState<AnalyzedApplication | null>(null);

  const activeApp = selectedApp || applications[0] || null;

  const handleWebScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!webUrl.trim()) return;
    setLoading(true);
    setError(null);
    try {
      await scanWebAppAndSave(webUrl.trim());
      setWebUrl('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Web scan failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleManifestScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!appName.trim() || !packageId.trim() || !manifestContent.trim()) return;
    setLoading(true);
    setError(null);
    try {
      await scanManifestAndSave({
        name: appName.trim(),
        packageId: packageId.trim(),
        developer: developer.trim() || 'Disclosed Developer',
        version: version.trim() || '1.0.0',
        platform,
        manifestContent,
        policyUrl: policyUrl.trim(),
      });
      setAppName('');
      setPackageId('');
      setManifestContent('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Manifest scan failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleManifestFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setManifestContent(text.slice(0, 60000));
    if (!appName) setAppName(file.name.replace(/\.(xml|plist|json|txt)$/i, ''));
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Application Privacy Scanner
            </h2>
            <p className="text-xs text-slate-400">
              Inspect live web origins or analyze AndroidManifest.xml, iOS Info.plist, and desktop permission manifests with transparent scoring criteria.
            </p>
          </div>
          <div className="flex items-center gap-1 p-1 bg-[#060C18] border border-slate-800 rounded-lg self-start">
            <button
              type="button"
              onClick={() => setScanMode('web')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                scanMode === 'web'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Globe className="w-3.5 h-3.5 inline mr-1.5" />
              Live Web Origin
            </button>
            <button
              type="button"
              onClick={() => setScanMode('manifest')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                scanMode === 'manifest'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode2 className="w-3.5 h-3.5 inline mr-1.5" />
              App Manifest / Permissions
            </button>
          </div>
        </div>

        {scanMode === 'web' ? (
          <form onSubmit={handleWebScan} className="flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              value={webUrl}
              onChange={(e) => setWebUrl(e.target.value)}
              placeholder="https://example.com"
              className="flex-1 px-3.5 py-2.5 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
            />
            <button
              type="submit"
              disabled={loading || !webUrl.trim()}
              className="px-5 py-2.5 text-sm font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              {loading ? 'Scanning Live HTML & DNS...' : 'Scan Web Application'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleManifestScan} className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <input
                type="text"
                value={appName}
                onChange={(e) => setAppName(e.target.value)}
                placeholder="Application Name"
                required
                className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
              />
              <input
                type="text"
                value={packageId}
                onChange={(e) => setPackageId(e.target.value)}
                placeholder="Package / Bundle ID (e.g. com.example.app)"
                required
                className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
              />
              <select
                value={platform}
                onChange={(e) => setPlatform(e.target.value as PlatformType)}
                className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-sky-500"
              >
                <option value="android">Android</option>
                <option value="ios">iOS</option>
                <option value="windows">Windows</option>
                <option value="macos">macOS</option>
                <option value="linux">Linux</option>
              </select>
              <input
                type="text"
                value={developer}
                onChange={(e) => setDeveloper(e.target.value)}
                placeholder="Developer / Publisher"
                className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
              />
              <input
                type="text"
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                placeholder="Version (e.g. 4.2.1)"
                className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
              />
              <input
                type="url"
                value={policyUrl}
                onChange={(e) => setPolicyUrl(e.target.value)}
                placeholder="Privacy Policy URL (optional)"
                className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Paste AndroidManifest.xml, Info.plist, or permission list</span>
                <label className="text-sky-400 hover:text-sky-300 cursor-pointer font-medium">
                  Upload Manifest File
                  <input
                    type="file"
                    accept=".xml,.plist,.json,.txt"
                    onChange={handleManifestFileUpload}
                    className="hidden"
                  />
                </label>
              </div>
              <textarea
                rows={4}
                value={manifestContent}
                onChange={(e) => setManifestContent(e.target.value)}
                placeholder="Paste <uses-permission android:name='android.permission.CAMERA' /> or NSLocationWhenInUseUsageDescription..."
                className="w-full px-3 py-2 text-xs font-mono bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>

            <button
              type="submit"
              disabled={loading || !appName.trim() || !packageId.trim() || !manifestContent.trim()}
              className="px-5 py-2 text-sm font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition-colors"
            >
              {loading ? 'Analyzing Manifest...' : 'Analyze Application Manifest'}
            </button>
          </form>
        )}

        {error && (
          <div className="text-xs text-rose-300 bg-rose-950/40 border border-rose-500/30 rounded-lg px-3 py-2">
            {error}
          </div>
        )}
      </div>

      {/* Application Inventory + Detailed Privacy Score Breakdown */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        <div className="xl:col-span-5 bg-[#0B1426] border border-slate-800/90 rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-100">
              Scanned Applications ({applications.length})
            </h3>
          </div>
          {applications.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-400">
              No applications scanned yet. Scan a live website or upload an Android/iOS manifest above.
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {applications.map((app) => (
                <div
                  key={app.id}
                  onClick={() => setSelectedApp(app)}
                  className={`p-4 cursor-pointer transition-colors flex items-center justify-between gap-3 ${
                    activeApp?.id === app.id ? 'bg-sky-950/30' : 'hover:bg-slate-800/40'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-slate-100 truncate">
                      {app.name}
                    </div>
                    <div className="text-xs text-slate-400 flex items-center gap-2 mt-0.5">
                      <span className="font-mono truncate">{app.packageId}</span>
                      <span aria-hidden="true">·</span>
                      <span className="uppercase">{app.platform}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <div className="text-right">
                      <div
                        className={`text-base font-bold font-mono tabular-nums ${
                          app.privacyScore >= 80
                            ? 'text-emerald-400'
                            : app.privacyScore >= 55
                              ? 'text-amber-400'
                              : 'text-rose-400'
                        }`}
                      >
                        {app.privacyScore}/100
                      </div>
                      <div className="text-[11px] text-slate-500">Privacy Score</div>
                    </div>
                    <button
                      type="button"
                      aria-label={`Delete ${app.name}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        void deleteRecord('applications', app.id);
                      }}
                      className="p-1.5 text-slate-500 hover:text-rose-400 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="xl:col-span-7 bg-[#0B1426] border border-slate-800/90 rounded-xl p-5">
          {activeApp ? (
            <div className="space-y-5">
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    <span>{activeApp.developer}</span>
                    <span aria-hidden="true">·</span>
                    <span>v{activeApp.version}</span>
                    <span aria-hidden="true">·</span>
                    <span className="uppercase">{activeApp.platform}</span>
                    <span aria-hidden="true">·</span>
                    <span className="text-sky-400">{activeApp.evidenceType}</span>
                  </div>
                  <h3 className="text-lg font-bold text-slate-100 mt-1">{activeApp.name}</h3>
                  <p className="text-xs font-mono text-slate-400">{activeApp.packageId}</p>
                </div>
                <div className="text-right">
                  <div className="text-3xl font-bold font-mono tabular-nums text-sky-400">
                    {activeApp.privacyScore}
                    <span className="text-sm text-slate-400">/100</span>
                  </div>
                  <div className="text-xs text-slate-400">Transparent Score</div>
                </div>
              </div>

              {/* Transparent Scoring Criteria */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-slate-300">
                  Transparent Scoring Criteria Breakdown (100 baseline minus observed penalties)
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3">
                    <div className="text-slate-400">Permissions</div>
                    <div className="text-base font-mono tabular-nums text-slate-100 mt-1">
                      -{activeApp.permissionsPenalty} / 40
                    </div>
                  </div>
                  <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3">
                    <div className="text-slate-400">Third-Party Domains</div>
                    <div className="text-base font-mono tabular-nums text-slate-100 mt-1">
                      -{activeApp.thirdPartyPenalty} / 30
                    </div>
                  </div>
                  <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3">
                    <div className="text-slate-400">Background Activity</div>
                    <div className="text-base font-mono tabular-nums text-slate-100 mt-1">
                      -{activeApp.backgroundPenalty} / 15
                    </div>
                  </div>
                  <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3">
                    <div className="text-slate-400">Policy Disclosures</div>
                    <div className="text-base font-mono tabular-nums text-slate-100 mt-1">
                      -{activeApp.disclosurePenalty} / 15
                    </div>
                  </div>
                </div>
              </div>

              {/* Sensitive Device Capabilities Matrix */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-slate-300">
                    Sensitive Device Capabilities &amp; Advertising ID
                  </h4>
                  <span className="text-xs text-slate-400">
                    Ad ID Access: <strong className="text-slate-200">{activeApp.advertisingIdAccess}</strong>
                  </span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                  {SENSITIVE_GROUPS.map((grp) => {
                    const requested = activeApp.requestedPermissions.some((p) =>
                      grp.keys.some((k) => p.toUpperCase().includes(k))
                    );
                    const granted = activeApp.grantedPermissions.some((p) =>
                      grp.keys.some((k) => p.toUpperCase().includes(k))
                    );
                    return (
                      <div
                        key={grp.label}
                        className="bg-[#060C18] border border-slate-800 rounded-lg px-3 py-2"
                      >
                        <div className="text-slate-200 font-medium">{grp.label}</div>
                        <div className="text-[11px] mt-0.5 text-slate-400">
                          {granted ? (
                            <span className="text-amber-400">Granted (OS)</span>
                          ) : requested ? (
                            <span className="text-sky-400">Requested</span>
                          ) : (
                            <span className="text-slate-500">Not Requested</span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div className="flex items-center gap-2 text-xs text-slate-400 pt-1">
                  <Info className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                  <span>
                    Requesting a permission declares OS capability; it is never assumed to mean the application actively accessed that sensor data.
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3.5 space-y-2">
                  <div className="font-semibold text-slate-200">
                    Detected SDKs ({activeApp.detectedSdks.length})
                  </div>
                  {activeApp.detectedSdks.length === 0 ? (
                    <p className="text-slate-500">No known tracking or analytics SDK signatures detected.</p>
                  ) : (
                    <ul className="space-y-1 text-slate-300 font-mono">
                      {activeApp.detectedSdks.map((sdk) => (
                        <li key={sdk}>{sdk}</li>
                      ))}
                    </ul>
                  )}
                </div>

                <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3.5 space-y-2">
                  <div className="font-semibold text-slate-200">
                    External Domains Contacted ({activeApp.externalDomains.length})
                  </div>
                  {activeApp.externalDomains.length === 0 ? (
                    <p className="text-slate-500">No external domains observed.</p>
                  ) : (
                    <ul className="space-y-1 text-slate-300 font-mono max-h-32 overflow-y-auto">
                      {activeApp.externalDomains.map((dom) => (
                        <li key={dom}>{dom}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>

              <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3.5 space-y-2 text-xs">
                <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                  <Shield className="w-3.5 h-3.5 text-sky-400" />
                  Privacy Policy &amp; Retention Disclosures
                </div>
                {activeApp.policyUrl ? (
                  <a
                    href={activeApp.policyUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="text-sky-400 hover:underline break-all block"
                  >
                    {activeApp.policyUrl}
                  </a>
                ) : (
                  <p className="text-slate-500">No privacy policy URL detected.</p>
                )}
                <p className="text-slate-300">{activeApp.retentionDisclosure}</p>
                <p className="text-slate-400">{activeApp.sharingPractices}</p>
              </div>
            </div>
          ) : (
            <div className="py-12 text-center space-y-2">
              <AppWindow className="w-6 h-6 text-slate-500 mx-auto" />
              <p className="text-sm font-medium text-slate-200">No Application Selected</p>
              <p className="text-xs text-slate-400">
                Scan a live website or submit an application manifest to inspect permissions, SDKs, and privacy score criteria.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
