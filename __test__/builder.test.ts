import axios from 'axios';
import fs from 'fs';
import {
  test,
} from 'tap';

import Accessor from '../dist/accessor';
import Builder from '../dist/builder';
  
const delay = (ms: number) => { return new Promise(resolve => setTimeout(resolve, ms));};

test('# constructor', function(t) {

  t.test('## constructor - default config', function(t) {
    Accessor.detachRootCert();
    try {
      const builder = new Builder();
      const client = builder.build();
      t.ok(client);
    } catch (err) {
      t.fail();
    }
    t.end();
  });

  t.test('## constructor - set mds url', function(t) {
    try {
      const builder = new Builder({
        mdsUrl: new URL('https://mds.fidoalliance.org/'),
      });
      const client = builder.build();
      t.ok(client);
    } catch (err) {
      t.fail();
    }
    t.end();
  });

  t.test('## constructor - set mds filepath', async function(t) {
    Accessor.detachRootCert();
    try {
      const res = await axios.get('https://mds.fidoalliance.org/');
      fs.writeFileSync('./test-mds-blob.jwt', res.data, 'utf-8');  
      const builder = new Builder({
        mdsFile: './test-mds-blob.jwt',
      });
      const client = builder.build();
      t.ok(client);
    } catch (err) {
      t.fail();
    }

    await delay(2000);
    fs.unlinkSync('./test-mds-blob.jwt');
    t.end();
  });

  t.test('## constructor - specify access mds url', function(t) {
    Accessor.detachRootCert();
    try {
      const builder = new Builder({
        accessMds: 'url',
      });
      const client = builder.build();
      t.ok(client);
    } catch (err) {
      t.fail();
    }
    t.end();
  });

  t.test('## constructor - specify access mds file', function(t) {
    Accessor.detachRootCert();
    try {
      const builder = new Builder({
        accessMds: 'file',
      });
      const client = builder.build();
      t.ok(client);
    } catch (err) {
      t.fail();
    }
    t.end();
  });

  t.test('## constructor - specify access mds jwt', async function(t) {
    Accessor.detachRootCert();
    try {
      const res = await axios.get('https://mds.fidoalliance.org/');
      const builder = new Builder({
        accessMds: 'jwt',
        mdsJwt: res.data,
      });
      const client = builder.build();
      t.ok(client);
    } catch (err) {
      t.fail();
    }
    t.end();
  });

  t.test('## constructor - set root certificate url', function(t) {
    Accessor.detachRootCert();
    try {
      const builder = new Builder({
        rootUrl: new URL('http://secure.globalsign.com/cacert/root-r3.crt'),
      });
      const client = builder.build();
      t.ok(client);
    } catch (err) {
      t.fail();
    }
    t.end();
  });

  t.test('## constructor - set root certificate filepath', async function(t) {
    const response = await axios.get('http://secure.globalsign.com/cacert/root-r3.crt', { responseType : 'arraybuffer', });
    fs.writeFileSync('./test-root-r3.crt', response.data);  
    Accessor.detachRootCert();
    try {
      const builder = new Builder({
        rootFile: './test-root-r3.crt',
      });
      const client = builder.build();
      t.ok(client);
    } catch (err) {
      t.fail();
    }
    fs.unlinkSync('./test-root-r3.crt');
    t.end();
  });

  t.test('## constructor - set root certificate pem', async function(t) {
    const response = await axios.get('http://secure.globalsign.com/cacert/root-r3.crt', { responseType : 'arraybuffer', });
    const pem = ['-----BEGIN CERTIFICATE-----', response.data.toString('base64'), '-----END CERTIFICATE-----'].join('\n');
    Accessor.detachRootCert();
    try {
      const builder = new Builder({
        rootPem: pem,
      });
      const client = builder.build();
      t.ok(client);
    } catch (err) {
      t.fail();
    }
    t.end();
  });

  t.test('## constructor - specify access root certificate url', function(t) {
    Accessor.detachRootCert();
    try {
      const builder = new Builder({
        accessRootCertificate: 'url',
      });
      const client = builder.build();
      t.ok(client);
    } catch (err) {
      t.fail();
    }
    t.end();
  });

  t.test('## constructor - specify access root certificate file', function(t) {
    Accessor.detachRootCert();
    try {
      const builder = new Builder({
        accessRootCertificate: 'file',
      });
      const client = builder.build();
      t.ok(client);
    } catch (err) {
      t.fail();
    }
    t.end();
  });

  t.test('## constructor - specify access root certificate pem', async function(t) {
    const response = await axios.get('http://secure.globalsign.com/cacert/root-r3.crt', { responseType : 'arraybuffer', });
    const pem = ['-----BEGIN CERTIFICATE-----', response.data.toString('base64'), '-----END CERTIFICATE-----'].join('\n');
    Accessor.detachRootCert();
    try {
      const builder = new Builder({
        accessRootCertificate: 'pem',
        rootPem: pem,
      });
      const client = builder.build();
      t.ok(client);
    } catch (err) {
      t.fail();
    }
    t.end();
  });

  t.end();
});

test('# buildAsync', function(t) {

  t.test('## buildAsync', async function(t) {
    Accessor.detachRootCert();
    try {
      const builder = new Builder();
      const client = await builder.buildAsync();
      t.ok(client);
    } catch (err) {
      t.fail();
    }
    t.end();
  });

  t.end();
});
