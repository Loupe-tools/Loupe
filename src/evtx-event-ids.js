// evtx-event-ids.js — Windows Event-ID → human label + MITRE ATT&CK registry.
//
// Used by Timeline Mode (src/app/app-timeline.js) to annotate the "Event ID"
// column on EVTX files. Every entry yields:
//
//   - a short human summary (for drawer pills / click-through)
//   - a slightly longer canonical name (Microsoft-speak)
//   - the Windows channel it's typically emitted on (for disambiguation —
//     Security 4624 vs. Sysmon 1 both want their own metadata)
//   - a curated list of MITRE ATT&CK technique IDs. Techniques hydrate
//     through `MITRE.lookup()` (src/mitre.js), so adding a technique here
//     that isn't in mitre.js means the lookup falls back to a bare-id entry
//     — check both files when extending.
//
// Coverage is deliberately narrow: high-signal IDs that real SOC analysts
// triage every day. We skip chatty verbose IDs (e.g. 5156 firewall accept)
// unless they're security-relevant.
//
// Lookup strategy:
//   EvtxEventIds.lookup(id, channel)
//     1. try `<channel-normalised>:<id>`  (e.g. "sysmon:1", "security:4624")
//     2. try just `<id>` as a string key  (falls back for Security-dominant IDs)
//     3. return null
//
// Channel normalisation strips common prefixes:
//   "Microsoft-Windows-Sysmon/Operational" → "sysmon"
//   "Microsoft-Windows-PowerShell/Operational" → "powershell"
//   "Microsoft-Windows-TaskScheduler/Operational" → "taskscheduler"
//   "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" → "terminalservices"
//   "Microsoft-Windows-WMI-Activity/Operational" → "wmi-activity"
//   "Microsoft-Windows-Windows Defender/Operational" → "defender"
//   Everything else is lower-cased and slash-stripped.
//
// Zero dependencies beyond the global `MITRE` object exported by mitre.js.
// CSP-safe.

(function () {
  'use strict';

  // ── Channel normalisation ─────────────────────────────────────────────
  function normChannel(ch) {
    if (!ch) return '';
    const s = String(ch).trim();
    if (!s) return '';
    const low = s.toLowerCase();
    if (low === 'security') return 'security';
    if (low === 'system') return 'system';
    if (low === 'application') return 'application';
    if (low.indexOf('sysmon') >= 0) return 'sysmon';
    if (low.indexOf('powershell') >= 0) return 'powershell';
    if (low.indexOf('taskscheduler') >= 0) return 'taskscheduler';
    if (low.indexOf('terminalservices') >= 0 || low.indexOf('terminal-services') >= 0) return 'terminalservices';
    if (low.indexOf('wmi-activity') >= 0 || low.indexOf('wmi activity') >= 0) return 'wmi-activity';
    if (low.indexOf('defender') >= 0) return 'defender';
    if (low.indexOf('appxdeployment') >= 0) return 'appx';
    if (low.indexOf('bits-client') >= 0) return 'bits';
    if (low.indexOf('windows firewall') >= 0 || low.indexOf('firewall-with-advanced') >= 0) return 'firewall';
    return low.replace(/^microsoft-windows-/, '').replace(/\/.*$/, '');
  }

  // ── Event registry ────────────────────────────────────────────────────
  // Keys are `<channel>:<id>` OR bare `<id>` (used when the same ID only
  // meaningfully shows up on one channel, e.g. Security 4624).
  //
  // Fields:
  //   name     — canonical Microsoft name
  //   summary  — short analyst-friendly label (shown in the drawer pill)
  //   channel  — display label (may differ from the normalised key)
  //   category — coarse grouping: 'Logon', 'Process', 'Account', 'Policy',
  //              'Service', 'Scheduled Task', 'PowerShell', 'Log', 'Share',
  //              'Kerberos', 'Sysmon', 'RDP', 'WMI', 'Defender', 'Object'
  //   mitre    — array of MITRE technique IDs (resolve via MITRE.lookup)
  //   noisy    — optional hint that this ID is high-volume on healthy hosts
  const EVENTS = {
    // ── Security channel — Logon / logoff ─────────────────────────────
    '4624': { name: 'An account was successfully logged on',
              summary: 'Successful logon',
              channel: 'Security', category: 'Logon',
              mitre: ['T1078', 'T1021'], noisy: true },
    '4625': { name: 'An account failed to log on',
              summary: 'Failed logon',
              channel: 'Security', category: 'Logon',
              mitre: ['T1110', 'T1078'] },
    '4634': { name: 'An account was logged off',
              summary: 'Logoff',
              channel: 'Security', category: 'Logon', mitre: [], noisy: true },
    '4647': { name: 'User initiated logoff',
              summary: 'User-initiated logoff',
              channel: 'Security', category: 'Logon', mitre: [] },
    '4648': { name: 'A logon was attempted using explicit credentials',
              summary: 'Explicit-credential logon (RunAs / overpass-the-hash pivot)',
              channel: 'Security', category: 'Logon',
              mitre: ['T1078', 'T1550', 'T1021'] },
    '4672': { name: 'Special privileges assigned to new logon',
              summary: 'Admin/privileged logon',
              channel: 'Security', category: 'Logon',
              mitre: ['T1078.003', 'T1134'] },
    '4776': { name: 'The computer attempted to validate the credentials for an account',
              summary: 'NTLM authentication',
              channel: 'Security', category: 'Logon',
              mitre: ['T1110', 'T1078'] },

    // ── Security — Process creation / termination ─────────────────────
    '4688': { name: 'A new process has been created',
              summary: 'Process creation',
              channel: 'Security', category: 'Process',
              mitre: ['T1059', 'T1204.002'], noisy: true },
    '4689': { name: 'A process has exited',
              summary: 'Process exit',
              channel: 'Security', category: 'Process', mitre: [], noisy: true },

    // ── Security — Service installation ───────────────────────────────
    '4697': { name: 'A service was installed in the system',
              summary: 'Service installed',
              channel: 'Security', category: 'Service',
              mitre: ['T1543.003', 'T1569.002'] },

    // ── Security — Scheduled tasks ────────────────────────────────────
    '4698': { name: 'A scheduled task was created',
              summary: 'Scheduled task created',
              channel: 'Security', category: 'Scheduled Task',
              mitre: ['T1053.005'] },
    '4699': { name: 'A scheduled task was deleted',
              summary: 'Scheduled task deleted',
              channel: 'Security', category: 'Scheduled Task',
              mitre: ['T1053.005', 'T1070'] },
    '4700': { name: 'A scheduled task was enabled',
              summary: 'Scheduled task enabled',
              channel: 'Security', category: 'Scheduled Task',
              mitre: ['T1053.005'] },
    '4702': { name: 'A scheduled task was updated',
              summary: 'Scheduled task updated',
              channel: 'Security', category: 'Scheduled Task',
              mitre: ['T1053.005'] },

    // ── Security — Audit / log policy tampering ───────────────────────
    '1102': { name: 'The audit log was cleared',
              summary: '⚠ Audit log cleared',
              channel: 'Security', category: 'Log',
              mitre: ['T1070.001', 'T1562.002'] },
    '4719': { name: 'System audit policy was changed',
              summary: 'Audit policy changed',
              channel: 'Security', category: 'Policy',
              mitre: ['T1562.002'] },

    // ── Security — Account lifecycle ──────────────────────────────────
    '4720': { name: 'A user account was created',
              summary: 'User account created',
              channel: 'Security', category: 'Account',
              mitre: ['T1136.001'] },
    '4722': { name: 'A user account was enabled',
              summary: 'User account enabled',
              channel: 'Security', category: 'Account',
              mitre: ['T1098'] },
    '4723': { name: 'An attempt was made to change an account\u2019s password',
              summary: 'Password change attempt',
              channel: 'Security', category: 'Account',
              mitre: ['T1098'] },
    '4724': { name: 'An attempt was made to reset an account\u2019s password',
              summary: 'Password reset (admin-initiated)',
              channel: 'Security', category: 'Account',
              mitre: ['T1098'] },
    '4725': { name: 'A user account was disabled',
              summary: 'User account disabled',
              channel: 'Security', category: 'Account',
              mitre: ['T1098'] },
    '4726': { name: 'A user account was deleted',
              summary: 'User account deleted',
              channel: 'Security', category: 'Account',
              mitre: ['T1098', 'T1070'] },
    '4728': { name: 'A member was added to a security-enabled global group',
              summary: 'Added to global security group',
              channel: 'Security', category: 'Account',
              mitre: ['T1098.007', 'T1078.002'] },
    '4732': { name: 'A member was added to a security-enabled local group',
              summary: 'Added to local security group',
              channel: 'Security', category: 'Account',
              mitre: ['T1098.007', 'T1078.003'] },
    '4738': { name: 'A user account was changed',
              summary: 'User account changed',
              channel: 'Security', category: 'Account',
              mitre: ['T1098'] },
    '4740': { name: 'A user account was locked out',
              summary: 'Account lockout',
              channel: 'Security', category: 'Account',
              mitre: ['T1110'] },

    // ── Security — Kerberos / tickets ─────────────────────────────────
    '4768': { name: 'A Kerberos authentication ticket (TGT) was requested',
              summary: 'Kerberos TGT requested',
              channel: 'Security', category: 'Kerberos',
              mitre: ['T1558.003', 'T1078'] },
    '4769': { name: 'A Kerberos service ticket was requested',
              summary: 'Kerberos service ticket (TGS)',
              channel: 'Security', category: 'Kerberos',
              mitre: ['T1558.003', 'T1558'] },
    '4771': { name: 'Kerberos pre-authentication failed',
              summary: 'Kerberos pre-auth failure (AS-REP roasting?)',
              channel: 'Security', category: 'Kerberos',
              mitre: ['T1558.004', 'T1110'] },

    // ── Security — SMB / share access ─────────────────────────────────
    '5140': { name: 'A network share object was accessed',
              summary: 'Network share accessed',
              channel: 'Security', category: 'Share',
              mitre: ['T1021.002', 'T1135'] },
    '5145': { name: 'A network share object was checked for access',
              summary: 'Share access check (detailed audit)',
              channel: 'Security', category: 'Share',
              mitre: ['T1021.002', 'T1135'], noisy: true },

    // ── Security — WinRM / RDP / interactive discovery ────────────────
    '4798': { name: 'A user\u2019s local group membership was enumerated',
              summary: 'Local-group membership enumerated',
              channel: 'Security', category: 'Discovery',
              mitre: ['T1087.001'] },
    '4799': { name: 'A security-enabled local group membership was enumerated',
              summary: 'Local security-group enumeration',
              channel: 'Security', category: 'Discovery',
              mitre: ['T1087.001'] },
    '5379': { name: 'Credential Manager credentials were read',
              summary: 'Credential Manager read',
              channel: 'Security', category: 'Credential Access',
              mitre: ['T1555.004'] },
    '5447': { name: 'A Windows Filtering Platform filter was changed',
              summary: 'Windows Filtering Platform filter changed',
              channel: 'Security', category: 'Policy',
              mitre: ['T1562.004'] },

    // ── System channel ────────────────────────────────────────────────
    'system:7045': { name: 'A service was installed in the system',
                     summary: 'Service installed (System log)',
                     channel: 'System', category: 'Service',
                     mitre: ['T1543.003', 'T1569.002'] },
    'system:7036': { name: 'Service state change',
                     summary: 'Service started/stopped',
                     channel: 'System', category: 'Service', mitre: [], noisy: true },
    'system:7040': { name: 'Service start type changed',
                     summary: 'Service start-type changed',
                     channel: 'System', category: 'Service',
                     mitre: ['T1543.003'] },
    'system:104':  { name: 'The event log was cleared',
                     summary: '⚠ System log cleared',
                     channel: 'System', category: 'Log',
                     mitre: ['T1070.001', 'T1562.002'] },

    // ── Sysmon (Microsoft-Windows-Sysmon/Operational) ─────────────────
    'sysmon:1':  { name: 'Process Create',
                   summary: 'Sysmon: process create',
                   channel: 'Sysmon', category: 'Process',
                   mitre: ['T1059', 'T1204.002'], noisy: true },
    'sysmon:2':  { name: 'A process changed a file creation time',
                   summary: 'Sysmon: file-creation-time changed (timestomping?)',
                   channel: 'Sysmon', category: 'Defense Evasion',
                   mitre: ['T1070.006'] },
    'sysmon:3':  { name: 'Network connection',
                   summary: 'Sysmon: network connection',
                   channel: 'Sysmon', category: 'Network',
                   mitre: ['T1071'], noisy: true },
    'sysmon:4':  { name: 'Sysmon service state changed',
                   summary: 'Sysmon: service state changed',
                   channel: 'Sysmon', category: 'Service',
                   mitre: ['T1562.001'] },
    'sysmon:5':  { name: 'Process terminated',
                   summary: 'Sysmon: process terminated',
                   channel: 'Sysmon', category: 'Process', mitre: [], noisy: true },
    'sysmon:6':  { name: 'Driver loaded',
                   summary: 'Sysmon: driver loaded',
                   channel: 'Sysmon', category: 'Kernel',
                   mitre: ['T1547.006', 'T1014'] },
    'sysmon:7':  { name: 'Image loaded',
                   summary: 'Sysmon: image/DLL loaded',
                   channel: 'Sysmon', category: 'Execution',
                   mitre: ['T1574.001', 'T1574.002'], noisy: true },
    'sysmon:8':  { name: 'CreateRemoteThread',
                   summary: 'Sysmon: remote thread created (injection?)',
                   channel: 'Sysmon', category: 'Defense Evasion',
                   mitre: ['T1055'] },
    'sysmon:10': { name: 'Process accessed another process',
                   summary: 'Sysmon: process access (LSASS dump?)',
                   channel: 'Sysmon', category: 'Credential Access',
                   mitre: ['T1003.001', 'T1055'] },
    'sysmon:11': { name: 'FileCreate',
                   summary: 'Sysmon: file create',
                   channel: 'Sysmon', category: 'Collection',
                   mitre: ['T1105'], noisy: true },
    'sysmon:12': { name: 'Registry object created or deleted',
                   summary: 'Sysmon: registry create/delete',
                   channel: 'Sysmon', category: 'Persistence',
                   mitre: ['T1112', 'T1547.001'] },
    'sysmon:13': { name: 'Registry value set',
                   summary: 'Sysmon: registry value set',
                   channel: 'Sysmon', category: 'Persistence',
                   mitre: ['T1112', 'T1547.001'], noisy: true },
    'sysmon:14': { name: 'Registry key / value rename',
                   summary: 'Sysmon: registry key/value renamed',
                   channel: 'Sysmon', category: 'Persistence',
                   mitre: ['T1112'] },
    'sysmon:15': { name: 'FileCreateStreamHash (ADS)',
                   summary: 'Sysmon: alternate data stream created',
                   channel: 'Sysmon', category: 'Defense Evasion',
                   mitre: ['T1564.004'] },
    'sysmon:17': { name: 'Pipe created',
                   summary: 'Sysmon: named pipe created',
                   channel: 'Sysmon', category: 'Lateral Movement',
                   mitre: ['T1021'] },
    'sysmon:18': { name: 'Pipe connected',
                   summary: 'Sysmon: named pipe connected',
                   channel: 'Sysmon', category: 'Lateral Movement',
                   mitre: ['T1021'] },
    'sysmon:22': { name: 'DNS query',
                   summary: 'Sysmon: DNS query',
                   channel: 'Sysmon', category: 'Network',
                   mitre: ['T1071.004'], noisy: true },
    'sysmon:23': { name: 'FileDelete',
                   summary: 'Sysmon: file deleted',
                   channel: 'Sysmon', category: 'Defense Evasion',
                   mitre: ['T1070.004'] },
    'sysmon:25': { name: 'Process tampering',
                   summary: 'Sysmon: process tampering (hollowing?)',
                   channel: 'Sysmon', category: 'Defense Evasion',
                   mitre: ['T1055.012', 'T1055'] },

    // ── PowerShell Operational ────────────────────────────────────────
    'powershell:4103': { name: 'Module logging — pipeline execution',
                        summary: 'PowerShell module logging',
                        channel: 'PowerShell', category: 'PowerShell',
                        mitre: ['T1059.001'], noisy: true },
    'powershell:4104': { name: 'Scriptblock logging',
                        summary: 'PowerShell scriptblock logged',
                        channel: 'PowerShell', category: 'PowerShell',
                        mitre: ['T1059.001', 'T1027'] },
    'powershell:4105': { name: 'Scriptblock execution started',
                        summary: 'PowerShell scriptblock start',
                        channel: 'PowerShell', category: 'PowerShell',
                        mitre: ['T1059.001'] },
    'powershell:4106': { name: 'Scriptblock execution stopped',
                        summary: 'PowerShell scriptblock stop',
                        channel: 'PowerShell', category: 'PowerShell',
                        mitre: [] },

    // ── Classic PowerShell channel ────────────────────────────────────
    'powershell:400': { name: 'Engine state changed to Available',
                       summary: 'PowerShell engine started',
                       channel: 'PowerShell', category: 'PowerShell',
                       mitre: ['T1059.001'] },
    'powershell:600': { name: 'Provider started',
                       summary: 'PowerShell provider started',
                       channel: 'PowerShell', category: 'PowerShell',
                       mitre: ['T1059.001'] },

    // ── Task Scheduler Operational ────────────────────────────────────
    'taskscheduler:106': { name: 'Task registered',
                          summary: 'Task Scheduler: task registered',
                          channel: 'TaskScheduler', category: 'Scheduled Task',
                          mitre: ['T1053.005'] },
    'taskscheduler:140': { name: 'Task updated',
                          summary: 'Task Scheduler: task updated',
                          channel: 'TaskScheduler', category: 'Scheduled Task',
                          mitre: ['T1053.005'] },
    'taskscheduler:141': { name: 'Task deleted',
                          summary: 'Task Scheduler: task deleted',
                          channel: 'TaskScheduler', category: 'Scheduled Task',
                          mitre: ['T1053.005', 'T1070'] },
    'taskscheduler:200': { name: 'Action started',
                          summary: 'Task Scheduler: action started',
                          channel: 'TaskScheduler', category: 'Scheduled Task',
                          mitre: ['T1053.005'], noisy: true },

    // ── WMI-Activity Operational ──────────────────────────────────────
    'wmi-activity:5857': { name: 'WMI provider started',
                          summary: 'WMI provider started',
                          channel: 'WMI-Activity', category: 'WMI',
                          mitre: ['T1047'] },
    'wmi-activity:5858': { name: 'WMI operation failed',
                          summary: 'WMI operation failed',
                          channel: 'WMI-Activity', category: 'WMI',
                          mitre: ['T1047'] },
    'wmi-activity:5860': { name: 'WMI temporary subscription',
                          summary: 'WMI temporary event subscription',
                          channel: 'WMI-Activity', category: 'WMI',
                          mitre: ['T1546.003', 'T1047'] },
    'wmi-activity:5861': { name: 'WMI permanent subscription',
                          summary: '⚠ WMI permanent event subscription',
                          channel: 'WMI-Activity', category: 'WMI',
                          mitre: ['T1546.003'] },

    // ── Windows Defender ──────────────────────────────────────────────
    'defender:1116': { name: 'Malware detected',
                      summary: '⚠ Defender: malware detected',
                      channel: 'Defender', category: 'Defender',
                      mitre: ['T1204.002'] },
    'defender:1117': { name: 'Action taken on malware',
                      summary: 'Defender: action taken on malware',
                      channel: 'Defender', category: 'Defender', mitre: [] },
    'defender:5001': { name: 'Real-time protection disabled',
                      summary: '⚠ Defender: real-time protection disabled',
                      channel: 'Defender', category: 'Defender',
                      mitre: ['T1562.001'] },
    'defender:5007': { name: 'Defender configuration changed',
                      summary: 'Defender: configuration changed',
                      channel: 'Defender', category: 'Defender',
                      mitre: ['T1562.001'] },

    // ── Terminal Services / RDP ───────────────────────────────────────
    'terminalservices:21':   { name: 'Session logon succeeded',
                              summary: 'RDP logon succeeded',
                              channel: 'TerminalServices', category: 'RDP',
                              mitre: ['T1021.001'] },
    'terminalservices:22':   { name: 'Shell start notification',
                              summary: 'RDP shell start',
                              channel: 'TerminalServices', category: 'RDP',
                              mitre: ['T1021.001'] },
    'terminalservices:25':   { name: 'Session reconnection succeeded',
                              summary: 'RDP session reconnected',
                              channel: 'TerminalServices', category: 'RDP',
                              mitre: ['T1021.001'] },
    'terminalservices:1149': { name: 'User authentication succeeded',
                              summary: 'RDP: user authentication succeeded',
                              channel: 'TerminalServices', category: 'RDP',
                              mitre: ['T1021.001'] }
  };

  // ── Public lookup helper ──────────────────────────────────────────────
  function lookup(id, channel) {
    if (id == null) return null;
    const idStr = String(id).trim();
    if (!idStr) return null;
    const ch = normChannel(channel);
    const keyed = ch ? EVENTS[ch + ':' + idStr] : null;
    const rec = keyed || EVENTS[idStr] || null;
    if (!rec) return null;
    // Hydrate MITRE techniques via the global registry (so they get a URL).
    const MT = (typeof window !== 'undefined' && window.MITRE) ? window.MITRE : null;
    const techniques = [];
    if (Array.isArray(rec.mitre)) {
      for (const tid of rec.mitre) {
        if (!tid) continue;
        const info = MT ? MT.lookup(tid) : null;
        techniques.push(info || { id: tid, name: tid, tactic: '', url: '' });
      }
    }
    return {
      id: idStr,
      name: rec.name || '',
      summary: rec.summary || rec.name || '',
      channel: rec.channel || '',
      category: rec.category || '',
      noisy: !!rec.noisy,
      techniques
    };
  }

  // ── Plain-text multi-line tooltip for native title="" attribute ──────
  // Designed to be shown by the browser on hover — avoids any interactive
  // markup. Lines:
  //   "4624 — An account was successfully logged on"
  //   "Channel: Security · Logon"
  //   ""
  //   "MITRE ATT&CK:"
  //   "  T1078      Valid Accounts"
  //   "  T1021.001  Remote Desktop Protocol"
  function formatTooltip(rec) {
    if (!rec) return '';
    const lines = [];
    lines.push(rec.id + ' — ' + (rec.name || rec.summary || ''));
    const sub = [];
    if (rec.channel) sub.push('Channel: ' + rec.channel);
    if (rec.category) sub.push(rec.category);
    if (sub.length) lines.push(sub.join(' · '));
    if (rec.techniques && rec.techniques.length) {
      lines.push('');
      lines.push('MITRE ATT&CK:');
      // Pad IDs so the names align in the monospace tooltip.
      let maxLen = 0;
      for (const t of rec.techniques) if (t.id.length > maxLen) maxLen = t.id.length;
      for (const t of rec.techniques) {
        lines.push('  ' + t.id.padEnd(maxLen + 2) + (t.name || ''));
      }
    }
    return lines.join('\n');
  }

  window.EvtxEventIds = {
    lookup,
    formatTooltip,
    normChannel,
    EVENTS
  };
})();
