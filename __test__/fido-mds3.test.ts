import {
  test,
} from 'tap';
import FM3 from '../dist/fido-mds3'

test('AAGUID', async function (t) {
  const Client = new FM3.Builder().build();
  const data = await Client.findByAAGUID('9c835346-796b-4c27-8898-d6032f515cc5');
  if (data) {
    t.type(data, 'object');
    t.equal(data.aaguid, '9c835346-796b-4c27-8898-d6032f515cc5');
    t.end();  
  } else {
    t.fail('cannot fetch metadata.');
  }
});

test('AAID', async function (t) {
  const Client = new FM3.Builder().build();
  const data = await Client.findByAAID('0066#0001');
  if (data) {
    t.type(data, 'object');
    t.equal(data.aaid, '0066#0001');
    t.end();  
  } else {
    t.fail('cannot fetch metadata.');
  }
});

test('AttestationCertificateKeyIdentifier', async function (t) {
  const Client = new FM3.Builder().build();
  const data = await Client.findByAttestationCertificateKeyIdentifier('c889abd01627b98d2f7c1cd9d5d16d2d0262f696');
  if (data) {
    t.type(data, 'object');
    t.same(data.attestationCertificateKeyIdentifiers, ['c889abd01627b98d2f7c1cd9d5d16d2d0262f696']);
    t.end();  
  } else {
    t.fail('cannot fetch metadata.');
  }
});

test('Authenticator identifier FIDO2', async function (t) {
  const Client = new FM3.Builder().build();
  const data = await Client.findMetadata('9c835346-796b-4c27-8898-d6032f515cc5');
  if (data) {
    t.type(data, 'object');
    t.equal(data.aaguid, '9c835346-796b-4c27-8898-d6032f515cc5');
    t.end();  
  } else {
    t.fail('cannot fetch metadata.');
  }
});

test('Authenticator identifier UAF', async function (t) {
  const Client = new FM3.Builder().build();
  const data = await Client.findMetadata('0066#0001');
  console.log(data);
  if (data) {
    t.type(data, 'object');
    t.equal(data.aaid, '0066#0001');
    t.end();  
  } else {
    t.fail('cannot fetch metadata.');
  }
});

test('Authenticator identifier U2F', async function (t) {
  const Client = new FM3.Builder().build();
  const data = await Client.findMetadata('c889abd01627b98d2f7c1cd9d5d16d2d0262f696');
  if (data) {
    t.type(data, 'object');
    t.same(data.attestationCertificateKeyIdentifiers, ['c889abd01627b98d2f7c1cd9d5d16d2d0262f696']);
    t.end();  
  } else {
    t.fail('cannot fetch metadata.');
  }
});

// something is wrong
// test('refresh', async function (t) {
//   const Client = new FM3.Builder().build();
//   const data = await Client.findByAAGUID('9c835346-796b-4c27-8898-d6032f515cc5', true);
//   if (data) {
//     t.type(data, 'object');
//     t.equal(data.aaguid, '9c835346-796b-4c27-8898-d6032f515cc5');
//     t.end();  
//   } else {
//     t.fail('cannot fetch metadata.');
//   }
// });
