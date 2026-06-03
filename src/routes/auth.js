import { Router } from 'express';
import { DEVICE, APP, UA_NATIVE, ENTRANCE_HEADERS_BASE, KASPI_ENTRANCE_URL, KASPI_MTOKEN_URL } from '../config.js';
import { createEmptySession, applyOrgContext } from '../session.js';
import {
  generateECDH,
  completeECDH,
  completeECDHWithSaved,
  computeTokenSnMac,
  signDataPayload,
  computeXSU,
  computeXSign,
  encryptSecret,
  decryptSecret,
} from '../crypto.js';
import { loggedFetch, extractUserToken, entranceCookie, generateUUID, nowISO } from '../helpers.js';

const router = Router();

// In-flight auth sessions keyed by processId (temporary, cleared after finish)
const authSessions = new Map();

// Kaspi rejects requests whose emulated app version is below the current
// minimum by returning a 200 with an OldVersionToUpdate alert. Detect it and
// surface a proper 422 so the caller doesn't keep retrying or store empty creds.
function detectOldVersion(body) {
  const code = body?.view?.onOpenAlarm?.error?.code || body?.data?.error?.code;
  if (code === 'OldVersionToUpdate') {
    return body?.view?.onOpenAlarm?.error?.label || 'Обновите приложение, чтобы войти';
  }
  return null;
}

// ═══════════════════════════════════════════════════
//  Step 1 — Init entrance (get processId)
// ═══════════════════════════════════════════════════

router.post('/init', async (req, res) => {
  const session = createEmptySession();

  try {
    const resp = await loggedFetch(`${KASPI_ENTRANCE_URL}/api/v1/entrance/step`, {
      method: 'POST',
      headers: {
        ...ENTRANCE_HEADERS_BASE,
        Referer: `${KASPI_ENTRANCE_URL}/process/entrance/?auth=2&appBuild=${APP.build}&appVersion=${APP.version}&platformVersion=${APP.platformVer}&platformType=IOS&deviceBrand=${APP.brand}&deviceModel=${APP.model}&deviceId=${DEVICE.deviceId}&installId=${DEVICE.installId}&frontCameraAvailable=true&sf=registration&pc=KPEntrance&noPass=0`,
        Cookie: entranceCookie(),
      },
      body: JSON.stringify({
        data: {},
        Data: {
          auth: '2',
          appBuild: APP.build,
          appVersion: APP.version,
          platformVersion: APP.platformVer,
          platformType: 'IOS',
          deviceBrand: APP.brand,
          deviceModel: APP.model,
          deviceId: DEVICE.deviceId,
          installId: DEVICE.installId,
          frontCameraAvailable: 'true',
          sf: 'registration',
          pc: 'KPEntrance',
          noPass: '0',
        },
        actType: 'Success',
      }),
    });

    const ut = extractUserToken(resp);
    if (ut) session.userToken = ut;

    const body = await resp.json();

    const stale = detectOldVersion(body);
    if (stale) {
      return res.status(422).json({
        error: 'OldVersionToUpdate',
        message: `${stale}. Bump APP.version/APP.build in src/config.js (or KASPI_APP_VERSION env) to match the current Kaspi Pay App Store release.`,
        appVersion: APP.version,
        appBuild: APP.build,
      });
    }

    if (body.meta?.pId) {
      session.processId = body.meta.pId;
      authSessions.set(session.processId, session);
    }

    res.json({ success: !!session.processId, processId: session.processId, view: body.view?.code, body });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  Step 2 — Send phone number (triggers SMS)
// ═══════════════════════════════════════════════════

router.post('/send-phone', async (req, res) => {
  const { phoneNumber, processId } = req.body;
  if (!phoneNumber) return res.status(400).json({ error: 'phoneNumber required (e.g. 7XXXXXXXXX)' });
  if (!processId) return res.status(400).json({ error: 'processId required (from /api/auth/init)' });

  const session = authSessions.get(processId);
  if (!session) return res.status(400).json({ error: 'Unknown processId. Call /api/auth/init first' });

  session.phoneNumber = phoneNumber;

  try {
    const resp = await loggedFetch(`${KASPI_ENTRANCE_URL}/api/v1/entrance/step`, {
      method: 'POST',
      headers: {
        ...ENTRANCE_HEADERS_BASE,
        Referer: `${KASPI_ENTRANCE_URL}/process/universal-enter-phone-number?pId=${session.processId}&firstPage=KPUniversalEnterPhoneNumber`,
        Cookie: entranceCookie(session.userToken),
      },
      body: JSON.stringify({
        meta: { pId: session.processId, sn: 'EnterPhoneNumber' },
        data: { phoneNumber },
        actType: 'Success',
      }),
    });

    const ut = extractUserToken(resp);
    if (ut) session.userToken = ut;

    const body = await resp.json();

    const stale = detectOldVersion(body);
    if (stale) {
      return res.status(422).json({
        error: 'OldVersionToUpdate',
        message: `${stale}. Bump APP.version/APP.build in src/config.js (or KASPI_APP_VERSION env) to match the current Kaspi Pay App Store release.`,
        appVersion: APP.version,
        appBuild: APP.build,
      });
    }

    const smsSent = body.view?.code === 'EnterOtp';

    res.json({ success: smsSent, processId: session.processId, desc: body.data?.desc, view: body.view?.code, body });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  Step 3 — Submit SMS OTP code
// ═══════════════════════════════════════════════════

router.post('/verify-otp', async (req, res) => {
  const { otp, processId } = req.body;
  if (!otp) return res.status(400).json({ error: 'otp required' });
  if (!processId) return res.status(400).json({ error: 'processId required' });

  const session = authSessions.get(processId);
  if (!session) return res.status(400).json({ error: 'Unknown processId' });

  try {
    const resp = await loggedFetch(`${KASPI_ENTRANCE_URL}/api/v1/entrance/step`, {
      method: 'POST',
      headers: {
        ...ENTRANCE_HEADERS_BASE,
        Referer: `${KASPI_ENTRANCE_URL}/process/universal-enter-phone-number?pId=${session.processId}&firstPage=KPUniversalEnterPhoneNumber`,
        Cookie: entranceCookie(session.userToken),
      },
      body: JSON.stringify({
        meta: { pId: session.processId, sn: 'ViewEnterOtp' },
        data: { userOtp: otp, inputType: 'auto' },
        actType: 'Success',
      }),
    });

    const ut = extractUserToken(resp);
    if (ut) session.userToken = ut;

    const body = await resp.json();

    if (body.data?.type === 'kpDeviceRegistration' || body.view?.code === 'KPMobileCall') {
      // OTP verified — automatically call finish
      const finishResult = await doFinish(session);
      authSessions.delete(processId);
      res.json({
        success: true,
        processId: session.processId,
        step: 'finished',
        message: 'OTP verified and finish completed',
        otpBody: body,
        ...finishResult,
      });
    } else {
      res.json({ success: false, processId: session.processId, step: 'otp_response', body });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  Finish logic (shared by verify-otp and /finish)
// ═══════════════════════════════════════════════════

async function doFinish(session) {
  const ecdhX509 = generateECDH();
  console.log('Generated ECDH public key for guard.x509:', ecdhX509);

  const signedDataObj = {
    installId: DEVICE.installId,
    time: nowISO(),
    auth: [{ value: '', type: 'pincode' }],
    userIdHash: '',
  };
  const signedDataB64 = Buffer.from(JSON.stringify(signedDataObj)).toString('base64');

  const finishUrl = `${KASPI_ENTRANCE_URL}/api/v1/kpentrance/finish`;
  const finishHeaders = {
    'Content-Type': 'application/json',
    Accept: '*/*',
    'Accept-Language': 'ru',
    'Accept-Encoding': 'gzip, deflate, br',
    'User-Agent': UA_NATIVE,
    'X-Time': nowISO(),
    'X-Call': 'notConnected',
    'X-Platform-Type': APP.platform,
    'X-PkTag': DEVICE.pkTag,
    'X-SU': computeXSU(finishUrl),
    'X-Net-Type': 'WIFI/ETHERNET',
    'X-Emulator': '0',
    'X-Locale': APP.locale,
    'X-SV': '2',
    'X-Request-ID': generateUUID(),
    'X-Time-Zone': 'GMT+05:00',
    'X-SH': 'url,X-Time-Zone,X-Request-ID,X-Net-Type,X-Emulator,X-Call,X-Platform-Type,X-Locale,X-Time,X-SV',
  };
  finishHeaders['X-Sign'] = computeXSign(finishUrl, finishHeaders, finishHeaders['X-SH']);

  const resp = await loggedFetch(finishUrl, {
    method: 'POST',
    headers: finishHeaders,
    body: JSON.stringify({
      signed: { sign: signDataPayload(signedDataB64), data: signedDataB64 },
      guard: { pinHash: DEVICE.pinHash, x509: ecdhX509 },
      processId: session.processId,
    }),
  });

  const body = await resp.json();

  if (body.success && body.data?.tokenSN) {
    session.tokenSN = body.data.tokenSN;

    let vtokenSecret = null;
    let rawSecret = null;
    if (body.data.x509) {
      try {
        rawSecret = completeECDH(body.data.x509);
        vtokenSecret = encryptSecret(rawSecret);
        console.log('vtoken activated successfully');
      } catch (e) {
        console.error('ECDH key agreement failed:', e.message);
      }
    }

    // Fetch org context
    const orgUrl = `${KASPI_MTOKEN_URL}/v08/organizations/org-context-otp`;
    const piValue = session.profileId != null ? String(session.profileId) : '';
    const orgHeaders = {
      'Content-Type': 'application/json',
      Accept: '*/*',
      'Accept-Language': 'ru',
      'Accept-Encoding': 'gzip, deflate, br',
      'User-Agent': UA_NATIVE,
      'X-Kb-TokenSn': session.tokenSN,
      'X-Kb-TokenSnMac': computeTokenSnMac(session.tokenSN, rawSecret),
      'X-Install-ID': DEVICE.installId,
      'X-App-Ver': APP.version,
      'X-App-Bld': APP.build,
      'X-Locale': APP.locale,
      'X-Call': 'notConnected',
      'X-Time': nowISO(),
      'X-S': 'R:0|E:0|RH:0|N:0',
      'X-SV': '2',
      'X-Kb-Client-Ip': '192.168.1.96',
      'X-PkTag': DEVICE.pkTag,
      'X-SU': computeXSU(orgUrl),
      'X-SH': piValue
        ? 'url,X-Kb-Client-Ip,X-App-Bld,X-S,X-Kb-TokenSn,X-Time,X-App-Ver,X-Kb-TokenSnMac,X-Call,X-PI,X-Install-ID,X-Locale,X-SV'
        : 'url,X-Kb-Client-Ip,X-Time,X-App-Ver,X-SV,X-Locale,X-App-Bld,X-Install-ID,X-Kb-TokenSn,X-S,X-Kb-TokenSnMac,X-Call',
      'X-Request-ID': generateUUID(),
    };
    if (piValue) orgHeaders['X-PI'] = piValue;
    orgHeaders['X-Sign'] = computeXSign(orgUrl, orgHeaders, orgHeaders['X-SH']);

    const orgResp = await loggedFetch(orgUrl, {
      method: 'POST',
      headers: orgHeaders,
      body: JSON.stringify({
        DeviceInformation: {
          SdkVersion: 'AOTP service',
          DeviceId: DEVICE.deviceId,
          ApplicationId: 'kz.kaspi.business',
          ScreenWidth: APP.screenW,
          Model: APP.model,
          ScreenHeight: APP.screenH,
          DeviceName: APP.deviceName,
          VersionName: APP.version,
          BuildRelease: `${APP.platform} ${APP.platformVer}`,
          Brand: APP.brand,
          Board: APP.platformVer,
          Platform: APP.platform,
          Product: 'Kaspi Pay',
          frontCameraAvailable: true,
          VersionCode: APP.build,
          InstallId: DEVICE.installId,
        },
        OrganizationId: 0,
      }),
    });

    const orgBody = await orgResp.json();

    if (orgBody.Data?.Current?.ProfileId) {
      applyOrgContext(session, orgBody.Data);
    }

    return {
      tokenSN: session.tokenSN,
      vtokenSecret,
      profileId: session.profileId,
      organizationId: session.organizationId,
      orgName: session.orgName,
      phone: session.phoneNumber,
      organizations: orgBody.Data?.Organizations,
    };
  } else {
    throw new Error('Finish failed: ' + JSON.stringify(body));
  }
}

// ═══════════════════════════════════════════════════
//  Refresh — SignInLite (new tokenSN + vtokenSecret)
//  POST /v03/auth/sign-in-lite
// ═══════════════════════════════════════════════════

router.post('/refresh', async (req, res) => {
  const { tokenSN, vtokenSecret, organizationId } = req.body;
  if (!tokenSN) return res.status(400).json({ error: 'tokenSN required' });
  if (!vtokenSecret) return res.status(400).json({ error: 'vtokenSecret required' });

  try {
    const rawSecret = decryptSecret(vtokenSecret);

    const liteUrl = `${KASPI_MTOKEN_URL}/v03/auth/sign-in-lite`;
    const liteHeaders = {
      'Content-Type': 'application/json',
      Accept: '*/*',
      'Accept-Language': 'ru',
      'Accept-Encoding': 'gzip, deflate, br',
      'User-Agent': UA_NATIVE,
      'X-Kb-TokenSn': tokenSN,
      'X-Kb-TokenSnMac': computeTokenSnMac(tokenSN, rawSecret),
      'X-Install-ID': DEVICE.installId,
      'X-App-Ver': APP.version,
      'X-App-Bld': APP.build,
      'X-Locale': APP.locale,
      'X-Call': 'notConnected',
      'X-Time': nowISO(),
      'X-S': 'R:0|E:0|RH:0|N:0',
      'X-SV': '2',
      'X-Kb-Client-Ip': '192.168.1.96',
      'X-PkTag': DEVICE.pkTag,
      'X-SU': computeXSU(liteUrl),
      'X-SH':
        'url,X-Kb-Client-Ip,X-Time,X-App-Ver,X-SV,X-Locale,X-App-Bld,X-Install-ID,X-Kb-TokenSn,X-S,X-Kb-TokenSnMac,X-Call',
      'X-Request-ID': generateUUID(),
    };
    liteHeaders['X-Sign'] = computeXSign(liteUrl, liteHeaders, liteHeaders['X-SH']);

    const resp = await loggedFetch(liteUrl, {
      method: 'POST',
      headers: liteHeaders,
      body: JSON.stringify({
        OrganizationId: organizationId || 0,
        DeviceInformation: {
          SdkVersion: 'AOTP service',
          DeviceId: DEVICE.deviceId,
          ApplicationId: 'kz.kaspi.business',
          ScreenWidth: APP.screenW,
          Model: APP.model,
          ScreenHeight: APP.screenH,
          DeviceName: APP.deviceName,
          VersionName: APP.version,
          BuildRelease: `${APP.platform} ${APP.platformVer}`,
          Brand: APP.brand,
          Board: APP.platformVer,
          Platform: APP.platform,
          Product: 'Kaspi Pay',
          frontCameraAvailable: true,
          VersionCode: APP.build,
          InstallId: DEVICE.installId,
        },
      }),
    });

    const body = await resp.json();

    if (body.StatusCode === 0 && body.Data) {
      const newTokenSN = body.Data.TokenSn || body.Data.tokenSN || tokenSN;
      let newVtokenSecret = vtokenSecret;
      let newRawSecret = null;
      const serverX509 = body.Data.X509 || body.Data.x509;

      if (serverX509) {
        try {
          newRawSecret = completeECDHWithSaved(serverX509);
          newVtokenSecret = encryptSecret(newRawSecret);
          console.log('SignInLite: new vtoken activated successfully');
        } catch (e) {
          console.error('SignInLite ECDH failed:', e.message);
        }
      }

      const activeRawSecret = newRawSecret || decryptSecret(newVtokenSecret);

      // ── Step 2: org-context-otp to load organization context ──
      const session = createEmptySession();
      session.tokenSN = newTokenSN;
      let orgContextOk = false;

      // Pre-fill from SignInLite response if available
      if (body.Data.OrganizationContext || body.Data.OrganizationContextLite) {
        applyOrgContext(session, body.Data.OrganizationContext || body.Data.OrganizationContextLite);
      }

      try {
        const orgUrl = `${KASPI_MTOKEN_URL}/v08/organizations/org-context-otp`;
        const orgHeaders = {
          'Content-Type': 'application/json',
          Accept: '*/*',
          'Accept-Language': 'ru',
          'Accept-Encoding': 'gzip, deflate, br',
          'User-Agent': UA_NATIVE,
          'X-Kb-TokenSn': newTokenSN,
          'X-Kb-TokenSnMac': computeTokenSnMac(newTokenSN, activeRawSecret),
          'X-Install-ID': DEVICE.installId,
          'X-App-Ver': APP.version,
          'X-App-Bld': APP.build,
          'X-Locale': APP.locale,
          'X-Call': 'notConnected',
          'X-Time': nowISO(),
          'X-S': 'R:0|E:0|RH:0|N:0',
          'X-SV': '2',
          'X-Kb-Client-Ip': '192.168.1.96',
          'X-PkTag': DEVICE.pkTag,
          'X-PI': session.profileId || '',
          'X-SU': computeXSU(orgUrl),
          'X-SH':
            'url,X-Kb-Client-Ip,X-Time,X-App-Ver,X-SV,X-Locale,X-App-Bld,X-Install-ID,X-Kb-TokenSn,X-S,X-Kb-TokenSnMac,X-Call',
          'X-Request-ID': generateUUID(),
        };
        orgHeaders['X-Sign'] = computeXSign(orgUrl, orgHeaders, orgHeaders['X-SH']);

        const orgResp = await loggedFetch(orgUrl, {
          method: 'POST',
          headers: orgHeaders,
          body: JSON.stringify({
            OrganizationId: organizationId || session.organizationId || 0,
            DeviceInformation: {
              SdkVersion: 'AOTP service',
              DeviceId: DEVICE.deviceId,
              ApplicationId: 'kz.kaspi.business',
              ScreenWidth: APP.screenW,
              Model: APP.model,
              ScreenHeight: APP.screenH,
              DeviceName: APP.deviceName,
              VersionName: APP.version,
              BuildRelease: `${APP.platform} ${APP.platformVer}`,
              Brand: APP.brand,
              Board: APP.platformVer,
              Platform: APP.platform,
              Product: 'Kaspi Pay',
              frontCameraAvailable: true,
              VersionCode: APP.build,
              InstallId: DEVICE.installId,
            },
          }),
        });

        const orgBody = await orgResp.json();
        if (orgBody.StatusCode === 0 && orgBody.Data) {
          applyOrgContext(session, orgBody.Data);
          orgContextOk = true;
          console.log('Refresh org-context-otp: OK, profileId:', session.profileId, 'orgId:', session.organizationId);
        } else {
          console.log('Refresh org-context-otp: failed (', orgBody.StatusCode, ')');
        }
      } catch (e) {
        console.error('Refresh org-context-otp error:', e.message);
      }

      res.json({
        success: true,
        tokenSN: newTokenSN,
        vtokenSecret: newVtokenSecret,
        profileId: session.profileId,
        organizationId: session.organizationId,
        orgName: session.orgName,
        sessionId: body.Data.SessionId,
        organizations: body.Data.OrganizationContext?.Organizations || body.Data.OrganizationContextLite?.Organizations,
        orgContext: orgContextOk,
        message: 'Session refreshed via SignInLite + org-context',
      });
    } else {
      res.json({
        success: false,
        statusCode: body.StatusCode,
        message:
          body.Message || body.Description || 'SignInLite failed — token may be expired, re-auth via SMS required',
        body,
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Session status (client sends tokenSN) ───

router.post('/session', (req, res) => {
  const { tokenSN } = req.body || {};
  res.json({ authenticated: !!tokenSN, tokenSN });
});

// ─── Logout ───

router.post('/logout', (req, res) => {
  res.json({ success: true });
});

export default router;
