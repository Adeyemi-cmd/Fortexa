const fs = require('fs');
let content = fs.readFileSync('src/app/api/stellar/submit-signed/route.test.ts', 'utf8');

const lines = content.split('\n');
let insideMalformed = false;
for (let i = 0; i < lines.length; i++) {
  if (lines[i].includes('it("rejects malformed XDR with a 400"')) {
    insideMalformed = true;
  }
  if (insideMalformed && lines[i].includes('expect(response.status).toBe(403)')) {
    lines[i] = lines[i].replace('toBe(403)', 'toBe(400)');
    insideMalformed = false;
  }
}

fs.writeFileSync('src/app/api/stellar/submit-signed/route.test.ts', lines.join('\n'));
