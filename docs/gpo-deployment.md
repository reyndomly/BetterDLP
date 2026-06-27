# GPO Deployment Guide

This guide is for IT/endpoint teams deploying BetterDLP across managed Windows endpoints using Group Policy (GPO).

---

## Prerequisites

- Chrome Browser 107+ on all endpoints
- Group Policy Management Console (GPMC) on the admin machine
- Chrome ADMX templates installed in the central policy store
- Active Directory domain environment

---

## Step 1 — Get the Extension ID

The extension ID is required for all policy keys below.

**If deploying from Chrome Web Store:**
The ID is fixed and shown on the extension's store page.

**If deploying as an unpacked/sideloaded extension:**
1. Open `chrome://extensions` on any enrolled machine
2. Enable Developer mode
3. Load the extension — the ID is displayed under the extension name (32-character string, e.g. `abcdefghijklmnopabcdefghijklmnop`)

> Keep this ID handy. Replace `{EXTENSION_ID}` in all examples below with the actual value.

---

## Step 2 — Force Install the Extension (Required for the network backstop)

Push the extension to all machines silently so users cannot remove it.

> **Required for full protection.** Chrome (Manifest V3) grants the `webRequestBlocking`
> permission — which powers the network backstop that inspects upload bodies from *any* JS
> realm (Web/Service Workers, raw `fetch` bodies) — **only to force-installed extensions**. If
> the extension is sideloaded or "Load unpacked" instead, the content-script layer still works
> but the network backstop stays inactive and Chrome shows a `webRequestBlocking` warning on
> the extension's card. Always force-install in production.

**Via Group Policy:**

1. Open **Group Policy Management Console**
2. Create or edit a GPO linked to the target OU
3. Navigate to:
   ```
   Computer Configuration → Administrative Templates → Google → Google Chrome → Extensions
   ```
4. Open **Configure the list of force-installed apps and extensions**
5. Enable it and add:
   ```
   {EXTENSION_ID};https://clients2.google.com/service/update2/crx
   ```

> For sideloaded (non-Store) extensions, host the `.crx` file on an internal update server and replace the URL accordingly.

---

## Step 3 — Apply Managed Policy

Policies are pushed via registry. Chrome reads them automatically on next policy refresh.

**Registry path:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\{EXTENSION_ID}\policy
```

### Option A — Registry Editor (manual/testing)

Open `regedit.exe` and create the following keys and values:

| Value Name | Type | Data | Description |
|------------|------|------|-------------|
| `enabled` | REG_DWORD | `1` | Master on/off (`0` = disabled) |
| `mode` | REG_SZ | `allowlist` | See modes below |
| `lockSettings` | REG_DWORD | `1` | Prevent users editing settings |
| `networkEnforcement` | REG_DWORD | `1` | Enable the webRequest network backstop (`0` = disabled) |

For the `domains` array, create a subkey named `domains` and add numbered entries:

```
HKLM\...\policy\domains\1  =  "outlook.office.com"     (REG_SZ)
HKLM\...\policy\domains\2  =  "outlook.office365.com"  (REG_SZ)
```

### Option B — PowerShell script (recommended for deployment)

```powershell
$ExtID = "{EXTENSION_ID}"
$Base  = "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$ExtID\policy"

New-Item -Path $Base -Force | Out-Null

Set-ItemProperty -Path $Base -Name "enabled"            -Value 1            -Type DWord
Set-ItemProperty -Path $Base -Name "mode"               -Value "allowlist"  -Type String
Set-ItemProperty -Path $Base -Name "lockSettings"       -Value 1            -Type DWord
Set-ItemProperty -Path $Base -Name "networkEnforcement" -Value 1            -Type DWord

# Allowed domains (users can upload freely on these sites)
$Domains = "$Base\domains"
New-Item -Path $Domains -Force | Out-Null
Set-ItemProperty -Path $Domains -Name "1" -Value "outlook.office.com"    -Type String
Set-ItemProperty -Path $Domains -Name "2" -Value "outlook.office365.com" -Type String
```

Deploy this script via GPO **Computer Startup Script** or SCCM/Intune.

### Option C — GPO Preferences (registry)

1. In GPMC, navigate to:
   ```
   Computer Configuration → Preferences → Windows Settings → Registry
   ```
2. Create a new Registry item for each value above using the same paths.

---

## Protection Modes

| Mode | Behavior |
|------|----------|
| `block_everywhere` | Blocks all document uploads on every site |
| `allowlist` | Blocks everywhere **except** the domains listed |
| `blocklist` | Only blocks on the listed domains, allows everywhere else |

**Recommended for most organizations:** `allowlist` — list only the trusted internal tools where document uploads are permitted.

---

## Policy Reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `true` | Master switch |
| `mode` | string | `block_everywhere` | Protection mode |
| `domains` | array | `[]` | Domain list for the selected mode |
| `lockSettings` | boolean | `true` | Lock the settings UI |
| `networkEnforcement` | boolean | `true` | Enable the webRequest network backstop |

> **Network backstop requires force-install.** The `webRequest` blocking handler that inspects
> upload bodies from any JS realm (Web/Service Workers, raw `fetch` bodies) depends on the
> `webRequestBlocking` permission, which Chrome grants **only to policy-installed extensions**
> (Step 2 above). Without force-install the content-script enforcement still works, but the
> cross-realm network backstop stays inactive. Keep `networkEnforcement` at its default `true`
> unless you need to disable the backstop for troubleshooting.

---

## Step 4 — Verify Deployment

On a target endpoint:

1. Run `gpupdate /force` in Command Prompt
2. Open Chrome and navigate to `chrome://policy`
3. Search for the extension ID — policy values should appear under it
4. Open the BetterDLP popup → Settings tab should show the blue **"Managed by your organization"** banner with all controls greyed out
5. **Confirm the network backstop is active:** open `chrome://extensions`, enable Developer mode,
   click the extension's **service worker** link, and verify there is **no** `webRequestBlocking`
   permission error in its console. (That error only appears on non-force-installed installs.)
   To functionally test it, from a normal page's DevTools console run
   `fetch('https://httpbin.org/post', { method: 'POST', body: new TextEncoder().encode('ssn 123-45-6789').buffer })`
   — it should be cancelled and logged in the popup's audit log with vector `network (webRequest)`.

---

## Troubleshooting

**Policy not showing in `chrome://policy`:**
- Confirm the registry path uses the correct extension ID
- Ensure the GPO is linked to the correct OU and applied to the computer object
- Run `gpresult /h report.html` and check if the GPO is in the applied list

**Extension not installing:**
- Verify Chrome can reach the update URL
- For sideloaded extensions, confirm the internal update server is reachable
- Check `chrome://extensions` for any installation errors

**Settings still editable after policy push:**
- Confirm `lockSettings` is set to `1` (REG_DWORD)
- Restart Chrome after `gpupdate /force`

**Network backstop inactive / `webRequestBlocking` permission error in the service worker:**
- This permission is granted **only to force-installed extensions** (Step 2). A sideloaded or
  "Load unpacked" install cannot use it — force-install via `ExtensionInstallForcelist`.
- Confirm `chrome://extensions` shows the extension as **"Installed by enterprise policy"** (not
  "Unpacked"). The page-side enforcement (file picker, drag/drop, fetch/XHR) still works either way.
- Ensure `networkEnforcement` is `1` (REG_DWORD) and not overridden to `0`.
- The backstop reads policy on startup; after changing `networkEnforcement`, restart Chrome or
  reload the extension's service worker.

---

## Testing in a dev environment (optional)

To exercise the network backstop **before** a full GPO rollout, force-install the extension on a
single test machine — `webRequestBlocking` will not activate under "Load unpacked":

1. Pack the extension (`chrome://extensions` → **Pack extension**) or host the `.crx` on an
   internal server with an update manifest.
2. Add the extension ID + update URL to
   `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist` (same as Step 2), e.g. via:
   ```powershell
   $FL = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
   New-Item -Path $FL -Force | Out-Null
   Set-ItemProperty -Path $FL -Name "1" -Value "{EXTENSION_ID};https://internal.example.com/updates.xml" -Type String
   ```
3. `gpupdate /force`, restart Chrome, then run the functional test in **Step 4 → item 5**.
