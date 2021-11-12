const fs = require('fs');
const FM3 = require('../../index');

const client = new FM3.Builder().build();
client.refresh().then(() => {
  const json = JSON.parse(fs.readFileSync('../../package.json', 'utf8'));

  const date = new Date.toISOString().slice(0, 10).replace(/-/g, '');
  const version = json.version.substring(0, 5).concat(`-${date}`);
  json.version = version;
  fs.writeFileSync('../../package.json', JSON.stringify(json, null, 2));
}).catch((err) => {
  throw err;
});
