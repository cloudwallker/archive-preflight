// Real offline file report interactions. CLI validation remains Python's responsibility.
const {firefox}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {pathToFileURL}=require('node:url');

async function main(){
  const [report,output,injection]=process.argv.slice(2);if(!report||!output)throw Error('Pass report.html, evidence directory, and optional injection report.');
  fs.mkdirSync(output,{recursive:true});
  const browser=await firefox.launch({headless:true});
  try {
  const context=await browser.newContext({viewport:{width:1280,height:900},acceptDownloads:true,offline:true,reducedMotion:'reduce'});
  const page=await context.newPage(),errors=[],remote=[];
  page.on('pageerror',error=>errors.push(String(error)));page.on('request',request=>{if(/^https?:/i.test(request.url()))remote.push(request.url());});
  await page.goto(pathToFileURL(path.resolve(report)).href);
  await page.locator('.entry').first().waitFor();
  assert.equal(await page.locator('.entry').count(),10);
  await page.locator('#policy summary').click();
  assert.match(await page.locator('#policy').innerText(),/NAME_COLLISION/);
  await page.screenshot({path:path.join(output,'report-desktop.png'),fullPage:true});
  await page.locator('#search').fill('CON.txt');assert.equal(await page.locator('.entry').count(),1);
  await page.locator('#search').fill('');await page.locator('#risk').selectOption('blocked');assert.equal(await page.locator('.entry').count(),2);
  await page.locator('#risk').selectOption('all');await page.locator('#kind').selectOption('symlink');assert.equal(await page.locator('.entry').count(),1);
  await page.locator('#kind').selectOption('all');await page.locator('#collision').selectOption('yes');assert.ok(await page.locator('.entry').count()>=2);
  await page.locator('#collision').selectOption('all');await page.locator('#groups button').first().click();assert.equal(await page.locator('.entry').count(),1);
  await page.locator('#search').fill('');
  await page.locator('#e000001 summary').click();assert.match(await page.locator('#e000001 details').innerText(),/hex/);
  const first=page.locator('#e000001');await first.locator('input').first().fill('Reviewed.txt');
  await page.locator('#e000007 input').first().fill('deep-reviewed.txt');
  await first.locator('input[type="checkbox"]').uncheck();
  const candidate=await first.locator('select').nth(1).locator('option').nth(1).getAttribute('value');await first.locator('select').nth(1).selectOption(candidate);
  assert.equal(await first.locator('input[type="checkbox"]').isChecked(),true);
  const exported=await Promise.all([page.waitForEvent('download'),page.locator('#export').click()]);
  await exported[0].saveAs(path.join(output,'reviewed-draft.json'));
  let draft=JSON.parse(fs.readFileSync(path.join(output,'reviewed-draft.json'),'utf8'));
  assert.equal(draft.decisions[0].targetPath,'Reviewed.txt');assert.equal(draft.decisions[0].action,'rename');assert.equal(draft.decisions[0].nameConfirmed,true);assert.ok(!('planId' in draft));
  await page.locator('#e000002 input').first().fill('Reviewed.txt');
  const conflict=await Promise.all([page.waitForEvent('download'),page.locator('#export').click()]);await conflict[0].saveAs(path.join(output,'collision-draft.json'));
  await page.locator('#e000002 select').first().selectOption('skip');
  const skipped=await Promise.all([page.waitForEvent('download'),page.locator('#export').click()]);await skipped[0].saveAs(path.join(output,'skipped-draft.json'));
  draft=JSON.parse(fs.readFileSync(path.join(output,'skipped-draft.json'),'utf8'));assert.equal(draft.decisions[1].targetPath,null);
  await page.setViewportSize({width:390,height:844});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
  await page.screenshot({path:path.join(output,'report-mobile-390.png'),fullPage:true});
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path:path.join(output,'report-mobile-viewport.png')});
  await page.goto(pathToFileURL(path.resolve(report)).href);await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(()=>document.activeElement.className),'skip');
  await page.keyboard.press('Enter');assert.equal(await page.evaluate(()=>document.activeElement.id),'entries');
  await page.screenshot({path:path.join(output,'report-keyboard.png')});
  if(injection){await page.goto(pathToFileURL(path.resolve(injection)).href);await page.locator('.entry').first().waitFor();assert.equal(await page.locator('img').count(),0);assert.match(await page.locator('#entries').innerText(),/\\u001b|\\u202e/);await page.screenshot({path:path.join(output,'report-injection.png'),fullPage:true});}
  assert.deepEqual(errors,[]);assert.deepEqual(remote,[]);
  fs.writeFileSync(path.join(output,'browser-evidence.json'),JSON.stringify({browser:'Firefox',version:browser.version(),offline:true,remoteRequests:remote,pageErrors:errors,viewport390NoOverflow:true,keyboardSkipLink:true,realDownloads:['reviewed-draft.json','collision-draft.json','skipped-draft.json'],checks:20},null,2));
  console.log('20 offline browser checks passed; real screenshots and draft downloads saved.');
  } finally { await browser.close(); }
}
main().catch(error=>{console.error(error);process.exitCode=1;});
