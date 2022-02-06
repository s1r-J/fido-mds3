import axios from 'axios';
import {
  parse,
} from 'comment-json';
import fs from 'fs';
import path from 'path';
import {
  test,
} from 'tap';

import Accessor from '../dist/accessor';

const PEM = `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f
-----END CERTIFICATE-----
`;
const CONFIG = parse(fs.readFileSync(path.resolve(__dirname, '../config/config.json'), 'utf-8'));
const DOWNLOAD_URL = CONFIG.root.url;
const BLOB_JWT_URL = CONFIG.mds.url;

test('# setRootCertPem', function(t) {
  t.test('## setRootCertPem', function(t) {
    try {
      Accessor.setRootCertPem(PEM);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  }); 

  t.end();
});

test('# setRootCertFile', function(t) {
  t.test('## setRootCertFile', async function(t) {
    try {
      const response = await axios.get(DOWNLOAD_URL, { responseType : 'arraybuffer', });
      if (response.data == null) {
        t.fail();
      } else {
        fs.writeFileSync('./test-root-r3.crt', response.data);  
        Accessor.setRootCertFile('./test-root-r3.crt');
        fs.unlinkSync('./test-root-r3.crt');
        t.end();
      }
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  }); 

  t.end();
});

test('# setRootCertUrl', function(t) {
  t.test('## setRootCertUrl', async function(t) {
    try {
      await Accessor.setRootCertUrl(new URL(DOWNLOAD_URL));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  }); 

  t.end();
});

test('# fromJwt', function(t) {
  t.test('## fromJwt - valid', async function(t) {
    try {
      Accessor.detachRootCert();
      const res = await axios.get(BLOB_JWT_URL);
      if (typeof res.data === 'string') {
        await Accessor.fromJwt(res.data);
        t.end();
      } else {
        t.fail('Response is not valid form: ' + BLOB_JWT_URL);
      }
    } catch(err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## fromJwt - wrong format', async function(t) {
      const res = await axios.get(BLOB_JWT_URL);
      const blob = res.data;
      const [header, payload, signature] = blob.split('.');
      Accessor.detachRootCert();
      try {
        await Accessor.fromJwt(header + '.' + payload);
        t.fail();
      } catch (err) {
        if (err != null && err instanceof Error) {
          t.equal(err.name, 'FM3AccessError');
          t.equal(err.message, 'Blob JWT is wrong format.');
          t.end();
        } else {
          t.fail();
        }
      }
  });

  t.test('## fromJwt - set root cert pem', async function(t) {
    try {
      Accessor.setRootCertPem(PEM);
      const res = await axios.get(BLOB_JWT_URL);
      Accessor.fromJwt(res.data);
      t.end();
    } catch(err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.end();
});

test('# fromFile', function(t) {
  t.test('## fromFile', async function(t) {
    try {
      const res = await axios.get(BLOB_JWT_URL);
      fs.writeFileSync('./accessor-test-mds-blob.jwt', res.data, 'utf-8');
      await Accessor.fromFile('./accessor-test-mds-blob.jwt');
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
    fs.unlinkSync('./accessor-test-mds-blob.jwt');
  });

  t.end();
});

test('# fromUrl', function(t) {
  t.test('## fromUrl', async function(t) {
    try {
      await Accessor.fromUrl(new URL(BLOB_JWT_URL));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.end();
});

test('# toJsonObject', function(t) {
  t.test('## toJsonObject', async function(t) {
    try {
      await Accessor.fromUrl(new URL(BLOB_JWT_URL));
      const result = await Accessor.toJsonObject();
      t.match(result.legalHeader, /[a-zA-Z0-9 \.\/-:]+/);
      t.match(result.no, /[0-9]+/);
      t.match(result.nextUpdate, /[0-9]{4}-[0-1]{1}[0-9]{1}-[0-1]{1}[0-9]{1}/);
      t.ok(result.entries);
      t.end();
    } catch(err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.end();
});

test('# toFile', function(t) {
  t.test('## toFile', async function(t) {
    try {
      await Accessor.fromUrl(new URL(BLOB_JWT_URL));
      await Accessor.toFile('./test-payload.json');
      const jsonStr = fs.readFileSync('./test-payload.json', 'utf-8');
      const json = JSON.parse(jsonStr);
      t.ok(json);
      t.end();
    } catch(err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
    fs.unlinkSync('./test-payload.json');
  });

  t.end();
});

