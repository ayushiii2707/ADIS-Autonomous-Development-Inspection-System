// Checks the served application page: its script compiles, and the agreed
// product requirements (labels, options, navigation, providers) are present.
import assert from "node:assert/strict";
import test from "node:test";

import app from "../worker/index.js";

async function servedPage(env = {}) {
  const response = await app.fetch(new Request("http://localhost/"), env);
  assert.equal(response.status, 200);
  return response.text();
}

const count = (text, pattern) => (text.match(pattern) || []).length;

test("the served page script compiles", async () => {
  const page = await servedPage();
  const scripts = [...page.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]);
  assert.equal(scripts.length, 1);
  assert.doesNotThrow(() => new Function(scripts[0]));
});

test("every input pattern is a valid browser regular expression", async () => {
  const page = await servedPage();
  // The markup is built inside single-quoted JavaScript strings, so apply the
  // string's escape processing to get the attribute the browser actually sees.
  const patterns = [...page.matchAll(/pattern="([^"]*)"/g)].map((match) => match[1].replace(/\\(.)/g, "$1"));
  assert.ok(patterns.length > 0);
  // Browsers compile pattern attributes with the "v" flag.
  for (const pattern of patterns) assert.doesNotThrow(() => new RegExp(`^(?:${pattern})$`, "v"), pattern);
});

test("repository onboarding offers only GitHub and Bitbucket with the agreed labels", async () => {
  const page = await servedPage();
  assert.equal(count(page, />Check and add<\/button>/g), 2);
  assert.equal(count(page, /＋ Check/g), 0);
  assert.equal(count(page, /Azure/gi), 0);
  assert.ok(page.includes(">Select an option</option>"));
  assert.match(page, /services=\[\['Web',[^\]]*\],\['Mobile',[^\]]*\],\['API',[^\]]*\],\['Database',[^\]]*\],\['Service',[^\]]*\]\]/);
  assert.equal(count(page, /Work tracking/g), 0);
});

test("navigation exposes the two starting paths and the compact sidebar", async () => {
  const page = await servedPage();
  for (const label of ["I already have code", "I have an idea", "SWITCH PROJECT", "Logout", "Discover", "Verify", "Operate", "New session", ">⌂ &nbsp;Home</button>"]) {
    assert.ok(page.includes(label), `missing ${label}`);
  }
  assert.ok(page.includes("function toggleSidebar()"));
  assert.ok(page.includes("async function goDiscover()"));
  // The top navigation replaced the sidebar: Home leads to the two starting paths.
  assert.ok(page.includes('onclick="goHome()"') && page.includes('onclick="showWorkspace()">↔ SWITCH PROJECT</button>'));
  assert.match(page, /function goHome\(\)\{[^\n]*else showStartingPoint\(\)\}/);
});

test("the landing page leads to real sign up and log in, and the code path asks for a repository", async () => {
  const page = await servedPage();
  assert.ok(page.includes('href="#/signup">Sign up</a>') && page.includes('href="#/login">Log in</a>'));
  assert.ok(page.includes("api('/api/auth/'+mode,{method:'POST'"), "auth forms post to the account API");
  assert.ok(page.includes("api('/api/auth/logout',{method:'POST'"), "logout ends the server session");
  assert.ok(page.includes("function chooseCode(){if(state.connection)return showDashboard();setStage('code');showDashboard();connectPrompt()}"));
  assert.ok(page.includes("connectScreen(\\'github\\')") && page.includes("connectScreen(\\'bitbucket\\')"));
  assert.ok(!/<img[^>]+src="https?:/.test(page), "no external images, so the page CSP is unchanged");
});

test("saving setup always sends the connected repository, and a failed branch save is reported", async () => {
  const page = await servedPage();
  // A stale connection_id:null in state.setup must not override the connected repository.
  assert.ok(page.includes("body:JSON.stringify({...state.setup,connection_id:state.connection?.id||state.setup.connection_id||null,...patch})"));
  assert.match(page, /async function saveBranch\(branch\)\{[^}]*try\{await saveSetup\(\{selected_branch:branch\}\)/);
  assert.ok(page.includes("catch(error){state.setup.selected_branch=null;if(button)button.disabled=true;notify(error.message,false)}"));
});

test("the page shows no hardcoded person, and scanning opens the Operate page", async () => {
  const page = await servedPage();
  assert.doesNotMatch(page, /ayushi|TEST-A/i);
  assert.doesNotMatch(page, />Run scan</);
  assert.ok(!page.includes("Scanning not available yet"));
  assert.ok(page.includes('onclick="startScan()">Run full scan</button>'), "the dashboard scan row starts a scan");
  assert.ok(page.includes('onclick="goOperate()">Operate</button>'), "Operate in the top navigation opens the scans page");
  assert.ok(page.includes("async function startScan(){") && page.includes("await goOperate(data.run.id)"), "starting a scan redirects to Operate");
  assert.ok(page.includes("<th>Assessment</th>") && page.includes("<th>Scanner level</th>") && !page.includes("item.scannerSeverity"), "findings show the report's assessment and the scanner level separately");
  assert.match(page, /let viewer=\{"name":"Local user","role":"Owner","workspace":"My workspace","initials":"LU"\}/);
});
