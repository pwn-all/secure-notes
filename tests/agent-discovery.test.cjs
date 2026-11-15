'use strict';
// Files that tell AI agents how to use an instance: they must match the specs they follow and the files they point at.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { existsSync, readFileSync } = require('node:fs');
const path = require('node:path');

const site = path.join(__dirname, '..', 'website');
const read = (p) => readFileSync(path.join(site, p));

test('agent-skills index follows Agent Skills Discovery 0.2.0 and its digests match the files', () => {
  const index = JSON.parse(read('.well-known/agent-skills/index.json'));
  assert.equal(index.$schema, 'https://schemas.agentskills.io/discovery/0.2.0/schema.json');
  assert.ok(index.skills.length > 0);
  for (const skill of index.skills) {
    assert.match(skill.name, /^(?!.*--)[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/);
    assert.equal(skill.type, 'skill-md');
    assert.ok(skill.description.length > 0 && skill.description.length <= 1024);
    assert.match(skill.url, /^\/\.well-known\/agent-skills\//);
    const file = read(skill.url.slice(1));
    assert.equal(skill.digest, 'sha256:' + createHash('sha256').update(file).digest('hex'), `${skill.url} changed: update its digest`);
    const front = /^---\n([\s\S]*?)\n---\n/.exec(file.toString('utf8'));
    assert.ok(front, 'SKILL.md needs YAML frontmatter');
    assert.match(front[1], new RegExp(`^name: ${skill.name}$`, 'm'));
    assert.equal(/^description: (.*)$/m.exec(front[1])[1], skill.description);
  }
});

test('llms.txt and the page point agents at files that exist', () => {
  const llms = read('llms.txt').toString('utf8');
  assert.match(llms, /^# SecNote\n\n> /);
  for (const [, href] of llms.matchAll(/\]\(([^)]+)\)/g)) {
    if (/^https:/.test(href) || href === '/.well-known/api-catalog') continue; // remote or served by the backend
    assert.ok(existsSync(path.join(site, href.replace(/^\//, ''))), `${href} is missing`);
  }
  assert.match(read('index.html').toString('utf8'), /<link rel="alternate" type="text\/markdown" href="index\.md"/);
  // no MCP server card: SecNote has no MCP transport to describe
  assert.equal(existsSync(path.join(site, '.well-known/mcp')), false);
});
