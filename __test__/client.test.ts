import axios from 'axios';
import {
  test,
} from 'tap';

import Accessor from '../dist/accessor';
import Client from '../dist/client';
import MdsPayloadEntry from '../dist/models/mdsPayloadEntry';
import { FidoMds3Config } from '../dist/type';

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

const DEFAULT_CONFIG: FidoMds3Config = {
  mdsUrl: new URL('https://mds.fidoalliance.org/'),
  mdsFile: './data/blob.jwt',
  mdsJwt: undefined,

  payloadFile: './data/payload.json',

  rootUrl: new URL('http://secure.globalsign.com/cacert/root-r3.crt'),
  rootFile: './cert/root-r3.crt',
  rootPem: undefined,

  accessMds: 'url',
  accessRootCertificate: 'url',
};

test('# constructor', function(t) {

  t.test('## constructor - mds: url, root cert: url', function(t) {
    const option = {
      ...DEFAULT_CONFIG,
    };
    const client = new Client(option);
    t.ok(client);
    t.end();
  });

  t.test('## constructor - mds: file, root cert: file', function(t) {
    const option = {
      ...DEFAULT_CONFIG,
    };
    option.accessMds = 'file';
    option.accessRootCertificate = 'file';
    const client = new Client(option);
    t.ok(client);
    t.end();
  });

  t.test('## constructor - mds: jwt, root cert: pem', async function(t) {
    const option = {
      ...DEFAULT_CONFIG,
    };
    option.accessMds = 'jwt';
    option.mdsJwt = (await axios.get(DEFAULT_CONFIG.mdsUrl.toString())).data;
    option.accessRootCertificate = 'pem';
    option.rootPem = PEM;
    const client = new Client(option);
    t.ok(client);
    t.end();
  });

  // t.test('## constructor error - jwt is not set', function(t) {
  //   const option = {
  //     ...DEFAULT_CONFIG,
  //   };
  //   option.accessMds = 'jwt';
  //   try {
  //     console.log('call!!!');
  //     const client = new Client(option);
  //   } catch (err) {
  //     if (err != null && err instanceof Error) {
  //       t.equal(err.name, 'FM3SettingError');
  //       t.equal(err.message, 'Please set mds jwt.');
  //       t.end();
  //     } else {
  //       t.fail('no error');
  //     }
  //   }
  // });

  // t.test('## constructor error - pem is not set', function(t) {
  //   const option = {
  //     ...DEFAULT_CONFIG,
  //   };
  //   option.accessRootCertificate = 'pem';
  //   Accessor.detachRootCert();
  //   try {
  //     const client = new Client(option);
  //   } catch (err) {
  //     console.log('here');
  //     if (err != null && err instanceof Error) {
  //       t.equal(err.name, 'FM3SettingError');
  //       t.equal(err.message, 'Please set root certificate pem.');
  //       t.end();
  //     } else {
  //       t.fail();
  //     }
  //   }
  // });

  t.end();
});

test('# create', function(t) {

  t.test('## create', async function(t) {
    const client = await Client.create(DEFAULT_CONFIG);
    t.ok(client);
    t.end();
  });

  t.end();
});

test('# aaguid', function(t) {

  t.test('## entry found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findByAAGUID('d8522d9f-575b-4866-88a9-ba99fa02f35b');
    if (ent != null) {
      t.ok(ent);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## entry not found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findByAAGUID('notfound');
    t.notOk(ent);
    t.end();
  });

  t.end();
});

test('# aaguid model', function(t) {

  t.test('## entry found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findModelByAAGUID('d8522d9f-575b-4866-88a9-ba99fa02f35b');
    if (ent != null) {
      t.ok(ent);
      t.ok(ent instanceof MdsPayloadEntry);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## entry not found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findModelByAAGUID('notfound');
    t.notOk(ent);
    t.end();
  });

  t.test('## refresh true', async function(t) {
    const client = await Client.create(DEFAULT_CONFIG);
    const ent = await client.findModelByAAGUID('d8522d9f-575b-4866-88a9-ba99fa02f35b', true);
    if (ent != null) {
      t.ok(ent);
      t.ok(ent instanceof MdsPayloadEntry);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## refresh false', async function(t) {
    const client = await Client.create(DEFAULT_CONFIG);
    const ent = await client.findModelByAAGUID('d8522d9f-575b-4866-88a9-ba99fa02f35b', false);
    if (ent != null) {
      t.ok(ent);
      t.ok(ent instanceof MdsPayloadEntry);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## refresh needed', async function(t) {
    const client = await Client.create(DEFAULT_CONFIG);
    const ent = await client.findModelByAAGUID('d8522d9f-575b-4866-88a9-ba99fa02f35b', 'needed');
    if (ent != null) {
      t.ok(ent);
      t.ok(ent instanceof MdsPayloadEntry);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## refresh force', async function(t) {
    const client = await Client.create(DEFAULT_CONFIG);
    const ent = await client.findModelByAAGUID('d8522d9f-575b-4866-88a9-ba99fa02f35b', 'force');
    if (ent != null) {
      t.ok(ent);
      t.ok(ent instanceof MdsPayloadEntry);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## refresh error', async function(t) {
    const client = await Client.create(DEFAULT_CONFIG);
    const ent = await client.findModelByAAGUID('d8522d9f-575b-4866-88a9-ba99fa02f35b', 'error');
    if (ent != null) {
      t.ok(ent);
      t.ok(ent instanceof MdsPayloadEntry);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## refresh error throws', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    try {
      const ent = await client.findModelByAAGUID('d8522d9f-575b-4866-88a9-ba99fa02f35b', 'error');
    } catch (err) {
      if (err != null && err instanceof Error) {
        t.equal(err.name, 'FM3OldDataError');
        t.equal(err.message, 'Metadata is old. Update at undefined');
        t.end();
      } else {
        t.fail();
      }
    }
  });

  t.end();
});

test('# aaid', function(t) {

  t.test('## entry found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findByAAID('4e4e#4005');
    if (ent != null) {
      t.ok(ent);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## entry not found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findByAAID('notfound');
    t.notOk(ent);
    t.end();
  });

  t.end();
});

test('# aaid model', function(t) {

  t.test('## entry found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findModelByAAID('4e4e#4005');
    if (ent != null) {
      t.ok(ent);
      t.ok(ent instanceof MdsPayloadEntry);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## entry not found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findModelByAAID('notfound');
    t.notOk(ent);
    t.end();
  });

  t.end();
});

test('# attestationCertificateKeyIdentifier', function(t) {

  t.test('## entry found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findByAttestationCertificateKeyIdentifier('1434d2f277fe479c35ddf6aa4d08a07cbce99dd7');
    if (ent != null) {
      t.ok(ent);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## entry not found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findByAttestationCertificateKeyIdentifier('notfound');
    t.notOk(ent);
    t.end();
  });

  t.end();
});

test('# attestationCertificateKeyIdentifier model', function(t) {

  t.test('## entry found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findModelByAttestationCertificateKeyIdentifier('1434d2f277fe479c35ddf6aa4d08a07cbce99dd7');
    if (ent != null) {
      t.ok(ent);
      t.ok(ent instanceof MdsPayloadEntry);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## entry not found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findModelByAttestationCertificateKeyIdentifier('notfound');
    t.notOk(ent);
    t.end();
  });

  t.end();
});

test('# metadata', function(t) {

  t.test('## entry found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findMetadata('d8522d9f-575b-4866-88a9-ba99fa02f35b');
    if (ent != null) {
      t.ok(ent);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## entry not found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findMetadata('notfound');
    t.notOk(ent);
    t.end();
  });

  t.end();
});

test('# metadata model', function(t) {

  t.test('## entry found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findMetadataModel('d8522d9f-575b-4866-88a9-ba99fa02f35b');
    if (ent != null) {
      t.ok(ent);
      t.ok(ent instanceof MdsPayloadEntry);
      t.end();
    } else {
      t.fail();
    }
  });

  t.test('## entry not found', async function(t) {
    const client = new Client(DEFAULT_CONFIG);
    const ent = await client.findMetadataModel('notfound');
    t.notOk(ent);
    t.end();
  });

  t.end();
});
