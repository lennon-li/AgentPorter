/* Synthetic-profile browser validation; never attach to an owner's browser. */
import {writeFile} from 'node:fs/promises';
const [port, origin, screenshot, exchangeKey] = process.argv.slice(2);
const target = await (await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(origin + '/index.html')}`, {method:'PUT'})).json();
const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
let next = 0;
const pending = new Map(), requests = [];
socket.onmessage = event => {
  const message = JSON.parse(event.data);
  if (message.method === 'Network.requestWillBeSent') requests.push(message.params.request.url);
  if (message.id && pending.has(message.id)) {
    const {resolve, reject, timer} = pending.get(message.id);
    clearTimeout(timer); pending.delete(message.id);
    if (message.error) reject(new Error(JSON.stringify(message.error)));
    else resolve(message.result);
  }
};
function call(method, params={}) {
  return new Promise((resolve, reject) => {
    const id = ++next;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('Browser command timed out: ' + method)); }, 15000);
    pending.set(id, {resolve, reject, timer});
    socket.send(JSON.stringify({id, method, params}));
  });
}
async function evaluate(expression) {
  const result = await call('Runtime.evaluate', {expression, returnByValue:true, awaitPromise:true});
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
}
async function until(expression) {
  const end = Date.now() + 15000;
  while (Date.now() < end) {
    if (await evaluate(expression)) return;
    await new Promise(resolve => setTimeout(resolve, 30));
  }
  throw new Error('Browser state did not arrive: ' + expression);
}
async function click(id) {
  const point = await evaluate(`(() => {const e=document.getElementById(${JSON.stringify(id)}); e.scrollIntoView({block:'center'}); const r=e.getBoundingClientRect(); return {x:r.x+r.width/2,y:r.y+r.height/2};})()`);
  await call('Input.dispatchMouseEvent', {type:'mousePressed', ...point, button:'left', clickCount:1});
  await call('Input.dispatchMouseEvent', {type:'mouseReleased', ...point, button:'left', clickCount:1});
}
try {
  await call('Page.enable'); await call('Runtime.enable'); await call('Network.enable');
  await call('Emulation.setDeviceMetricsOverride', {width:430,height:1000,deviceScaleFactor:1,mobile:true});
  await call('Page.navigate', {url:origin + '/index.html'});
  await until(`document.getElementById('create-key') && !document.getElementById('create-key').disabled`);
  await click('create-key');
  await until(`/^[0-9a-f]{64}$/.test(document.getElementById('public-key').value)`);
  const publicKey = await evaluate(`document.getElementById('public-key').value`);
  const privateExportDenied = await evaluate(`(async () => {
    const database=await new Promise((resolve,reject)=>{const r=indexedDB.open('agentporter-owner-device-v1',1);r.onsuccess=()=>resolve(r.result);r.onerror=reject;});
    try { const pair=await new Promise((resolve,reject)=>{const r=database.transaction('keys','readonly').objectStore('keys').get('owner');r.onsuccess=()=>resolve(r.result);r.onerror=reject;});
      try {await crypto.subtle.exportKey('pkcs8',pair.privateKey);return false;} catch {return true;}
    } finally {database.close();}
  })()`);
  await call('Page.reload', {ignoreCache:true});
  await until(`document.getElementById('public-key')?.value === ${JSON.stringify(publicKey)}`);
  const persisted = await evaluate(`document.getElementById('create-key').disabled`);
  // Allow the fixture to install this synthetic device's public key in its
  // protected policy before creating the exact policy-bound push proposal.
  if (exchangeKey === '--exchange-key') console.log(JSON.stringify({publicKey}));
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  await call('Page.navigate', {url:origin + '/index.html#proposal=invalid!'});
  await until(`document.getElementById('status')?.textContent.startsWith('Could not load proposal link:')`);
  const malformedLinkDenied = await evaluate(`document.getElementById('acknowledge').disabled && document.getElementById('approve').disabled && document.getElementById('receipt').value === ''`);
  await call('Page.navigate', {url:origin + '/index.html#proposal=' + Buffer.from(input, 'utf8').toString('base64url')});
  await until(`document.getElementById('proposal')?.value === ${JSON.stringify(input)} && document.getElementById('public-key')?.value === ${JSON.stringify(publicKey)}`);
  const linkedProposalRequiresReview = await evaluate(`document.getElementById('acknowledge').disabled && document.getElementById('approve').disabled && document.getElementById('receipt').value === '' && location.hash === ''`);
  await click('review');
  await until(`!document.getElementById('acknowledge').disabled`);
  const noInjectedElements = await evaluate(`document.querySelectorAll('#details img,#details script').length===0`);
  const initiallyDisabled = await evaluate(`document.getElementById('approve').disabled`);
  const reviewedDetails = await evaluate(`document.getElementById('details').textContent`);
  await evaluate(`document.getElementById('acknowledge').checked=true;document.getElementById('acknowledge').dispatchEvent(new Event('change'));document.getElementById('approve').click();`);
  const syntheticClickDenied = await evaluate(`document.getElementById('receipt').value === ''`);
  await evaluate(`document.getElementById('acknowledge').checked=false;document.getElementById('acknowledge').dispatchEvent(new Event('change'));`);
  await click('acknowledge'); await click('approve');
  await until(`document.getElementById('receipt').value.length > 100`);
  const receipt = await evaluate(`document.getElementById('receipt').value`);
  await evaluate(`window.scrollTo(0,0)`);
  const picture = await call('Page.captureScreenshot', {format:'png',captureBeyondViewport:true});
  await writeFile(screenshot, Buffer.from(picture.data, 'base64'));
  await evaluate(`document.getElementById('proposal').value+=' ';document.getElementById('proposal').dispatchEvent(new Event('input',{bubbles:true}));`);
  const changedProposalInvalidated = await evaluate(`document.getElementById('approve').disabled && !document.getElementById('acknowledge').checked && document.getElementById('receipt').value===''`);
  const externalRequests = requests.filter(url => !url.startsWith(origin + '/'));
  console.log(JSON.stringify({publicKey, receipt, persisted, privateExportDenied,
    noInjectedElements, initiallyDisabled, syntheticClickDenied, changedProposalInvalidated, malformedLinkDenied, linkedProposalRequiresReview, externalRequests, reviewedDetails}));
} finally { socket.close(); }
