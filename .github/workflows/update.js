const axios = require('axios');
const fs = require('fs');
const FM3 = require('../../index');

(async () => {
  const mdsResponse = await axios.get('https://mds.fidoalliance.org/');
  fs.writeFileSync('./data/blob.jwt', mdsResponse.data, 'utf-8');

  const accessor = FM3.Accessor;
  await accessor.setRootCertUrl('http://secure.globalsign.com/cacert/root-r3.crt');
  await accessor.fromJwt(mdsResponse.data);
  await accessor.toFile('./data/payload.json');

  const json = JSON.parse(fs.readFileSync('./package.json', 'utf-8'));
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const version = json.version.substring(0, 5).concat(`-${date}`);
  json.version = version;
  fs.writeFileSync('./package.json', JSON.stringify(json, null, 2));
})();
