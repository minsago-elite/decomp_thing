#!/usr/bin/env node
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.DECOMP_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const [htmlPath, output] = process.argv.slice(2);
  assert(htmlPath && output, 'usage: verify-authentication-browser.cjs <dashboard.html> <new-evidence-dir>');
  fs.mkdirSync(path.dirname(output), {recursive: true}); fs.mkdirSync(output);
  const html = fs.readFileSync(htmlPath, 'utf8');
  const css = fs.readFileSync(htmlPath + '.css', 'utf8');
  assert(css.length > 0, 'production stylesheet fixture is empty');
  const browser = await chromium.launch({headless: true});
  const browserVersion = browser.version();
  let starts = 0, polls = 0, cancellations = 0, cancellationFailure = null, pollingFailure = null, admissionStatus = 202, omitAdmissionIdentity = false, replacementId = null, admissionFailure = null, inspectionId = '00000000-0000-0000-0000-000000000001', context;
  try {
    context = await browser.newContext();
    await context.tracing.start({screenshots: true, snapshots: true});
    const page = await context.newPage();
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    let mode = 'ready';
    await page.route('**/*', route => {
      const request = route.request(), url = new URL(request.url());
      if (url.pathname === '/') return route.fulfill({contentType:'text/html', body:html});
      if (url.pathname === '/assets/app.css') return route.fulfill({contentType:'text/css', body:css});
      if (url.pathname === '/api/operator/auth-methods/cancel') {
        assert.equal(request.headers()['x-decomp-operator-action'], 'cancel-auth-inspection');
        assert.equal(request.headers()['x-decomp-inspection-id'], inspectionId);
        cancellations++;
        if (cancellationFailure === 'http') return route.fulfill({status:503, body:'unavailable'});
        if (cancellationFailure === 'network') return route.abort('failed');
        mode = 'cancelled';
        // Let polling publish the terminal result before the cancellation acknowledgement arrives.
        return new Promise(resolve => setTimeout(resolve, 600)).then(() =>
          route.fulfill({status:202, json:{status:'cancellation-requested'}}));
      }
      if (url.pathname !== '/api/operator/auth-methods') return route.abort();
      if (request.method() === 'POST') {
        starts++;
        if (admissionStatus === 202) inspectionId = `00000000-0000-0000-0000-${String(starts).padStart(12, '0')}`;
        if (admissionFailure === 'network') return route.abort('failed');
        assert.equal(request.headers()['x-decomp-operator-action'], 'inspect-auth');
        return route.fulfill({status:admissionStatus, json:{status:'inspecting', ...(omitAdmissionIdentity ? {} : {inspectionId})}});
      }
      polls++;
      if (pollingFailure === 'http') return route.fulfill({status:503, body:'unavailable'});
      if (pollingFailure === 'network') return route.abort('failed');
      if (pollingFailure === 'json') return route.fulfill({status:200, contentType:'application/json', body:'{' });
      const polledId = replacementId || inspectionId;
      if (mode === 'idle') return route.fulfill({json:{status:'idle', inspectionId:null}});
      if (mode === 'waiting' || mode === 'cancelled')
        return route.fulfill({json:{status:mode === 'waiting' ? 'inspecting' : 'cancelled', inspectionId:polledId}});
      return route.fulfill({json: mode === 'failed' ? {status:'failed'} : {
        status:'ready',
        methods: mode === 'empty' ? [] : mode === 'logout' ? [] : [{
          idPreview:'method', variant:'agent', namePreview:'<img src=x> login', descriptionPreview:'[redacted]'
        }],
        logoutAdvertised: mode === 'empty' ? false : mode === 'logout' ? true : undefined,
        logoutSupported: mode === 'empty' ? false : mode === 'logout' ? false : undefined
      }});
    });
    const click = async expected => {
      await page.locator('#inspect-auth-methods').click();
      await page.waitForFunction(text => document.querySelector('#auth-inspection-status').textContent === text,
        expected, {timeout:10000});
      assert.equal(await page.locator('#inspect-auth-methods').isEnabled(), true);
    };
    await page.goto('http://auth.fixture/');
    assert.equal(await page.evaluate(() => [...document.styleSheets].some(sheet =>
      sheet.href && new URL(sheet.href).pathname === '/assets/app.css' && sheet.cssRules.length > 0)), true);
    assert.equal(await page.evaluate(() => getComputedStyle(document.body).margin), '0px');
    assert.equal(await page.evaluate(() => parseFloat(getComputedStyle(document.querySelector('.shell')).marginLeft) > 0), true);
    await page.waitForTimeout(500);
    assert.equal(starts, 0); assert.equal(polls, 0);
    await click('Advertised method previews. Login is unsupported; no login attempted.');
    assert.equal(await page.locator('#auth-method-list li').count(), 1);
    assert.equal(await page.locator('#auth-method-list img').count(), 0);
    mode='failed';
    await click('Authentication inspection is unavailable. Check ACP configuration and cleanup.');
    assert.equal(await page.locator('#auth-method-list li').count(), 0);
    mode='empty';
    await click('No authentication methods advertised; no login attempted.');
    assert.equal(await page.locator('#auth-method-list li').count(), 0);
    assert.equal(starts, 3); assert.equal(polls, 3);
    mode='logout';
    await click('No authentication methods advertised; the agent advertised logout. Login is unsupported; no login attempted.');
    assert.equal(await page.locator('#auth-method-list li').count(), 1);
    assert.equal(await page.locator('#auth-method-list li').textContent(),
      'Logout advertised · logout remains unsupported here');
    assert.equal(starts, 4); assert.equal(polls, 4);
    mode = 'waiting';
    await page.locator('#inspect-auth-methods').click();
    await page.waitForFunction(() => !document.querySelector('#cancel-auth-inspection').disabled);
    for (const failure of ['http', 'network', 'json']) {
      pollingFailure = failure;
      const previousPolls = polls;
      await page.waitForFunction(() => document.querySelector('#auth-inspection-status').textContent ===
        'Inspection status is unavailable; retrying. Cancellation remains available.');
      while (polls <= previousPolls) await page.waitForTimeout(50);
      assert.equal(await page.locator('#cancel-auth-inspection').isEnabled(), true);
      assert.equal(await page.locator('#inspect-auth-methods').isEnabled(), false);
    }
    pollingFailure = null;
    await page.waitForFunction(() => document.querySelector('#auth-inspection-status').textContent ===
      'Inspecting advertised methods…');
    for (const failure of ['http', 'network']) {
      cancellationFailure = failure;
      await page.locator('#cancel-auth-inspection').click();
      await page.waitForFunction(() => !document.querySelector('#cancel-auth-inspection').disabled &&
        document.querySelector('#auth-inspection-status').textContent ===
          'Cancellation request failed; inspection status is still being checked.');
      assert.equal(await page.locator('#inspect-auth-methods').isEnabled(), false);
    }
    cancellationFailure = null;
    await page.locator('#cancel-auth-inspection').click();
    await page.waitForFunction(() => document.querySelector('#auth-inspection-status').textContent ===
      'Inspection cancelled; no login attempted.');
    await page.waitForTimeout(800);
    assert.equal(await page.locator('#auth-inspection-status').textContent(), 'Inspection cancelled; no login attempted.');
    assert.equal(await page.locator('#inspect-auth-methods').isEnabled(), true);
    assert.equal(await page.locator('#cancel-auth-inspection').isEnabled(), false);
    assert.equal(cancellations, 3); assert.equal(starts, 5); assert.deepEqual(errors, []);
    admissionStatus = 409; mode = 'waiting';
    await page.locator('#inspect-auth-methods').click();
    await page.waitForFunction(() => !document.querySelector('#cancel-auth-inspection').disabled);
    assert.equal(await page.locator('#inspect-auth-methods').isEnabled(), false);
    await page.locator('#cancel-auth-inspection').click();
    await page.waitForFunction(() => document.querySelector('#auth-inspection-status').textContent ===
      'Inspection cancelled; no login attempted.');
    await page.waitForTimeout(800);
    assert.equal(starts, 6); assert.equal(cancellations, 4);
    assert.equal(await page.locator('#cancel-auth-inspection').isEnabled(), false);
    admissionStatus = 202; mode = 'waiting'; omitAdmissionIdentity = true; pollingFailure = 'http';
    await page.locator('#inspect-auth-methods').click();
    await page.waitForFunction(() => document.querySelector('#auth-inspection-status').textContent ===
      'Inspection status is unavailable; retrying.');
    assert.equal(await page.locator('#cancel-auth-inspection').isEnabled(), false);
    pollingFailure = null;
    await page.waitForFunction(() => !document.querySelector('#cancel-auth-inspection').disabled);
    await page.locator('#cancel-auth-inspection').click();
    await page.waitForFunction(() => document.querySelector('#auth-inspection-status').textContent ===
      'Inspection cancelled; no login attempted.');
    await page.waitForTimeout(800);
    assert.equal(starts, 7); assert.equal(cancellations, 5);
    assert.deepEqual(errors, []);
    admissionStatus = 202; mode = 'waiting'; omitAdmissionIdentity = false; replacementId = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
    await page.locator('#inspect-auth-methods').click();
    await page.waitForFunction(() => !document.querySelector('#cancel-auth-inspection').disabled);
    await page.waitForFunction(() => document.querySelector('#auth-inspection-status').textContent ===
      'This inspection is no longer active; start a new inspection.');
    assert.equal(await page.locator('#inspect-auth-methods').isEnabled(), true);
    assert.equal(await page.locator('#cancel-auth-inspection').isEnabled(), false);
    assert.deepEqual(errors, []);
    replacementId = null;
    mode = 'empty';
    await click('No authentication methods advertised; no login attempted.');
    mode = 'waiting'; admissionFailure = 'network';
    await page.locator('#inspect-auth-methods').click();
    await page.waitForFunction(() => document.querySelector('#auth-inspection-status').textContent ===
      'Admission response was lost; checking inspection status…');
    await page.waitForFunction(() => document.querySelector('#auth-inspection-status').textContent ===
      'Inspecting advertised methods…');
    await page.waitForFunction(() => !document.querySelector('#cancel-auth-inspection').disabled);
    assert.equal(await page.locator('#inspect-auth-methods').isEnabled(), false);
    admissionFailure = null;
    await page.locator('#cancel-auth-inspection').click();
    await page.waitForFunction(() => document.querySelector('#auth-inspection-status').textContent ===
      'Inspection cancelled; no login attempted.');
    await page.waitForTimeout(800);
    assert.equal(starts, 9); assert.equal(cancellations, 6);
    assert.equal(await page.locator('#inspect-auth-methods').isEnabled(), true);
    assert.equal(await page.locator('#cancel-auth-inspection').isEnabled(), false);
    assert.deepEqual(errors, []);
    mode = 'idle'; admissionFailure = 'network';
    await page.locator('#inspect-auth-methods').click();
    await page.waitForFunction(() => document.querySelector('#auth-inspection-status').textContent ===
      'Authentication inspection is unavailable. Check ACP configuration and cleanup.');
    assert.equal(await page.locator('#inspect-auth-methods').isEnabled(), true);
    assert.equal(await page.locator('#cancel-auth-inspection').isEnabled(), false);
    assert.equal(starts, 10);
    assert.deepEqual(errors, []);
    admissionFailure = null;
    await page.screenshot({path:path.join(output,'dashboard.png')});
  } finally {
    try { if (context) await context.tracing.stop({path:path.join(output,'trace.zip')}); }
    finally { await browser.close(); }
  }
  fs.writeFileSync(path.join(output,'result.json'), JSON.stringify({passed:true,
<<<<<<< HEAD
    browser:browserVersion, starts, polls, cancellations, scenarios:['production stylesheet','explicit action','previews','text escaping','failure','retry','empty inventory','advertised logout','cancellation','HTTP cancellation retry','network cancellation retry','late cancellation acknowledgement','HTTP polling recovery','network polling recovery','invalid JSON polling recovery','attach to existing inspection','recover missing admission identity','replacement inspection rejected','restart after replacement rejection','lost admission recovered by polling','lost admission confirmed idle'],
    renderedCssSha256:require('node:crypto').createHash('sha256').update(css).digest('hex'),
    renderedHtmlSha256:require('node:crypto').createHash('sha256').update(html).digest('hex')},null,2)+'\n');
})().catch(error=>{console.error(error);process.exitCode=1;});
