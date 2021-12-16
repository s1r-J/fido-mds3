import {
  test,
} from 'tap';
import MdsPayloadEntry from '../../dist/models/mdsPayloadEntry';
import { FM3MetadataBLOBPayloadEntry } from '../../dist/type';

const FIDO2_PAYLOAD_ENTRY = '{"aaguid":"d8522d9f-575b-4866-88a9-ba99fa02f35b","metadataStatement":{"legalHeader":"https://fidoalliance.org/metadata/metadata-statement-legal-header/","aaguid":"d8522d9f-575b-4866-88a9-ba99fa02f35b","description":"YubiKey Bio Series","authenticatorVersion":328965,"protocolFamily":"fido2","schema":3,"upv":[{"major":1,"minor":0},{"major":1,"minor":1}],"authenticationAlgorithms":["secp256r1_ecdsa_sha256_raw","ed25519_eddsa_sha512_raw"],"publicKeyAlgAndEncodings":["cose"],"attestationTypes":["basic_full"],"userVerificationDetails":[[{"userVerificationMethod":"none"}],[{"userVerificationMethod":"presence_internal"},{"userVerificationMethod":"fingerprint_internal","baDesc":{"selfAttestedFRR":0.0,"selfAttestedFAR":0.0,"maxTemplates":5,"maxRetries":5,"blockSlowdown":0}}],[{"userVerificationMethod":"passcode_external","caDesc":{"base":64,"minLength":4,"maxRetries":8,"blockSlowdown":0}},{"userVerificationMethod":"presence_internal"}],[{"userVerificationMethod":"presence_internal"}],[{"userVerificationMethod":"passcode_external","caDesc":{"base":64,"minLength":4,"maxRetries":8,"blockSlowdown":0}}],[{"userVerificationMethod":"fingerprint_internal","baDesc":{"selfAttestedFRR":0.0,"selfAttestedFAR":0.0,"maxTemplates":5,"maxRetries":5,"blockSlowdown":0}}]],"keyProtection":["hardware","secure_element"],"matcherProtection":["on_chip"],"cryptoStrength":128,"attachmentHint":["external","wired"],"tcDisplay":[],"attestationRootCertificates":["MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbwnebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXwLvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJhjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kthX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2kLVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1UsG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqcU9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw=="],"icon":"data:image/png;base64,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","authenticatorGetInfo":{"versions":["FIDO_2_0","FIDO_2_1_PRE","FIDO_2_1"],"extensions":["credProtect","hmac-secret","largeBlobKey","credBlob","minPinLength"],"aaguid":"d8522d9f575b486688a9ba99fa02f35b","options":{"plat":false,"rk":true,"clientPin":false,"up":true,"uv":false,"pinUvAuthToken":true,"largeBlobs":true,"bioEnroll":false,"userVerificationMgmtPreview":false,"authnrCfg":true,"credMgmt":true,"credentialMgmtPreview":true,"setMinPINLength":true,"makeCredUvNotRqd":false,"alwaysUv":true},"maxMsgSize":1200,"pinUvAuthProtocols":[2,1],"maxCredentialCountInList":8,"maxCredentialIdLength":128,"transports":["usb"],"algorithms":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-8}],"maxSerializedLargeBlobArray":1024,"minPINLength":4,"firmwareVersion":328965,"maxCredBlobLength":32,"maxRPIDsForSetMinPINLength":1,"preferredPlatformUvAttempts":3,"uvModality":2,"remainingDiscoverableCredentials":25}},"statusReports":[{"status":"FIDO_CERTIFIED","effectiveDate":"2021-08-06"},{"status":"FIDO_CERTIFIED_L1","effectiveDate":"2021-08-06","url":"www.yubico.com","certificationDescriptor":"YubiKey Bio","certificateNumber":"FIDO20020210806001","certificationPolicyVersion":"1.3","certificationRequirementsVersion":"1.4"}],"timeOfLastStatusChange":"2021-08-10"}';
const UAF_PAYLOAD_ENTRY = '{"aaid":"4e4e#4005","metadataStatement":{"legalHeader":"https://fidoalliance.org/metadata/metadata-statement-legal-header/","aaid":"4e4e#4005","description":"Touch ID, Face ID, or Passcode","authenticatorVersion":256,"protocolFamily":"uaf","schema":3,"upv":[{"major":1,"minor":0},{"major":1,"minor":1}],"authenticationAlgorithms":["rsa_emsa_pkcs1_sha256_raw"],"publicKeyAlgAndEncodings":["rsa_2048_raw"],"attestationTypes":["basic_surrogate"],"userVerificationDetails":[[{"userVerificationMethod":"passcode_internal","caDesc":{"base":10,"minLength":4,"maxRetries":5,"blockSlowdown":60}}],[{"userVerificationMethod":"fingerprint_internal","baDesc":{"selfAttestedFRR":0.0,"selfAttestedFAR":0.0,"maxTemplates":0,"maxRetries":5,"blockSlowdown":0}}]],"keyProtection":["hardware","tee"],"matcherProtection":["tee"],"attachmentHint":["internal"],"tcDisplay":["any"],"tcDisplayContentType":"text/plain","attestationRootCertificates":[],"icon":"data:image/png;base64,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"},"statusReports":[{"status":"NOT_FIDO_CERTIFIED","effectiveDate":"2018-05-19"}],"timeOfLastStatusChange":"2018-05-19"}';
const U2F_PAYLOAD_ENTRY = '{"attestationCertificateKeyIdentifiers":["1434d2f277fe479c35ddf6aa4d08a07cbce99dd7"],"metadataStatement":{"legalHeader":"https://fidoalliance.org/metadata/metadata-statement-legal-header/","attestationCertificateKeyIdentifiers":["1434d2f277fe479c35ddf6aa4d08a07cbce99dd7"],"description":"NEOWAVE Winkeo FIDO2","authenticatorVersion":2,"protocolFamily":"u2f","schema":3,"upv":[{"major":1,"minor":1}],"authenticationAlgorithms":["secp256r1_ecdsa_sha256_raw"],"publicKeyAlgAndEncodings":["ecc_x962_raw"],"attestationTypes":["basic_full"],"userVerificationDetails":[[{"userVerificationMethod":"presence_internal"}]],"keyProtection":["hardware","secure_element"],"matcherProtection":["on_chip"],"cryptoStrength":128,"attachmentHint":["external","wired"],"tcDisplay":[],"attestationRootCertificates":["\\n\\n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"],"icon":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAACqUlEQVRIx2P8//8/Ay0BEwONwagFpFlw8cKFirIyR3t7S1Oz0KDgBfPm//z5k3izvn39lp+Ta2tltWTRIoTofxhYtXKllpq6srwCAikoRIVHvH379j9x4NSpU0AtQI1W5hZwQagPzp87V11ZiXAvIxj9Zzh54kRNZRWRPvj96xcDOM0zMTKiB9G8uXP//fsHNFRASLC+sXHm7Nlubu4Qm3bt3Llu7VpiLGCEmcuIacGZU6fB4cWQX1AQGx/n7OIyaeoUbV0diIvamluePXtGUST/+g32HSODhoYGRISFhaWppYWVlRUo+OHjh6b6BoosgHvqz58/cDl9ff3M7CwIe8+e3atXrqQgmeIokDKzs/X19EGy/xk6OzofP3pEWUbDsAYYRC3tbRwcHED2h/fv62pqCReOjCTmZE0trZy8XAj78KFDy5YuJd50VAsYcepKTU83NjWBqOnu7Hxw/wE+O/7jsgC315mZmRubm9nZ2YFqvnz+0lBfhzOg/qO7lQm/B+EAmHwLioogCo4cOrxk0WIiPUEgkpFBUnKymZk5hN3T1XX3zh1iYoKJcDTBA4qFubmtlYubC8j++vVrTVU1qHQhzQeMBHyhrKxcWFwMUXn61Kn5c+dSv8JJSEy0trGGsCf099+6dQsuxcLCCrH7P5IrSYgDeKFS39TEx8sHZH//9r2uGhFQN65fh2VPNoqqTCUlpeKyUmgxfPpMSWERMAMuX7asv7cXIqilrYXwFrxeg/qOuGZSdEzM3t17Dh06CPT0pk0bN23cCI9FYKZJz8hE98Hff38hDDY2diL90dHdpaurixawrCysre3tunq6iLTX0NAAToIsTx4/tndwiIyOAtYExFjAzc3t4+sLJL99/QosE0VFRe3s7RtbmoGVFUqcjTYdh78FAIhBLlNd7ju1AAAAAElFTkSuQmCC"},"statusReports":[{"status":"NOT_FIDO_CERTIFIED","effectiveDate":"2021-09-21"}],"timeOfLastStatusChange":"2021-09-21"}';

test('# constructor', function(t) {

  t.test('## constructor - JSON Object', function(t) {
    const json = JSON.parse(FIDO2_PAYLOAD_ENTRY);
    try {
      const ent = new MdsPayloadEntry(json);
      t.end();
    } catch (err) {
      t.fail('cannot create new instance by JSON Object');
    }
  });

  t.test('## constructor - JSON String', function(t) {
    try {
      const ent = new MdsPayloadEntry(FIDO2_PAYLOAD_ENTRY);
      t.end();
    } catch (err) {
      t.fail('cannot create new instance by JSON String');
    }
  });

  t.test('## constructor - Object', function(t) {
    const json = JSON.parse(FIDO2_PAYLOAD_ENTRY);
    const entry = json as FM3MetadataBLOBPayloadEntry;
    try {
      const ent = new MdsPayloadEntry(entry);
      t.end();
    } catch (err) {
      t.fail('cannot create new instance by Object');
    }
  });

  t.end();
});

test('# method - getPayloadEntry', function(t) {
  t.test('## method - getPayloadEntry', function(t) {
    const ent = new MdsPayloadEntry(FIDO2_PAYLOAD_ENTRY);
    const entry = ent.getPayloadEntry();
    t.ok(entry);
    t.end();
  });

  t.end();
});

test('# method - getAAGUID', function(t) {
  t.test('## method - getAAGUID FIDO2', function(t) {
    const ent = new MdsPayloadEntry(FIDO2_PAYLOAD_ENTRY);
    t.equal(ent.getAAGUID(), 'd8522d9f-575b-4866-88a9-ba99fa02f35b');
    t.notOk(ent.getAAID());
    t.notOk(ent.getAttestationCertificateKeyIdentifiers());
    t.end();
  });

  t.test('## method - getAAGUID UAF', function(t) {
    const ent = new MdsPayloadEntry(UAF_PAYLOAD_ENTRY);
    t.notOk(ent.getAAGUID());
    t.end();
  });

  t.test('## method - getAAGUID U2F', function(t) {
    const ent = new MdsPayloadEntry(U2F_PAYLOAD_ENTRY);
    t.notOk(ent.getAAGUID());
    t.end();
  });

  t.end();
});

test('# method - getAAID', function(t) {
  t.test('## method - getAAID FIDO2', function(t) {
    const ent = new MdsPayloadEntry(FIDO2_PAYLOAD_ENTRY);
    t.notOk(ent.getAAID());
    t.end();
  });

  t.test('## method - getAAID UAF', function(t) {
    const ent = new MdsPayloadEntry(UAF_PAYLOAD_ENTRY);
    t.equal(ent.getAAID(), '4e4e#4005');
    t.notOk(ent.getAAGUID());
    t.notOk(ent.getAttestationCertificateKeyIdentifiers());
    t.end();
  });

  t.test('## method - getAAID U2F', function(t) {
    const ent = new MdsPayloadEntry(U2F_PAYLOAD_ENTRY);
    t.notOk(ent.getAAID());
    t.end();
  });

  t.end();
});

test('# method - getAttestationCertificateKeyIdentifiers', function(t) {
  t.test('## method - getAttestationCertificateKeyIdentifiers FIDO2', function(t) {
    const ent = new MdsPayloadEntry(FIDO2_PAYLOAD_ENTRY);
    t.notOk(ent.getAttestationCertificateKeyIdentifiers());
    t.end();
  });

  t.test('## method - getAttestationCertificateKeyIdentifiers UAF', function(t) {
    const ent = new MdsPayloadEntry(UAF_PAYLOAD_ENTRY);
    t.notOk(ent.getAttestationCertificateKeyIdentifiers());
    t.end();
  });

  t.test('## method - getAttestationCertificateKeyIdentifiers U2F', function(t) {
    const ent = new MdsPayloadEntry(U2F_PAYLOAD_ENTRY);
    t.notOk(ent.getAAGUID());
    t.notOk(ent.getAAID());
    const acis = ent.getAttestationCertificateKeyIdentifiers();
    if (acis == null) {
      t.fail(('U2F AttestationCertificateKeyIdentifiers do not exist'));
    } else {
      t.equal(acis.length, 1);
      t.equal(acis[0], '1434d2f277fe479c35ddf6aa4d08a07cbce99dd7');
      t.end();
    }
  });

  t.end();
});

test('# method - getLatestStatusReport', function(t) {
  t.test('## method - getLatestStatusReport', function(t) {
    const ent = new MdsPayloadEntry(FIDO2_PAYLOAD_ENTRY);
    const sr = ent.getLatestStatusReport();
    t.ok(sr);
    if (sr.effectiveDate != null) {
      t.equal(sr.effectiveDate, '2021-08-06');
      t.equal(sr.status, 'FIDO_CERTIFIED_L1');
      t.end();
    } else {
      t.fail('effectiveDate');
    }
  });

  t.end();
});

test('# method - getLatestAuthenticatorStatus', function(t) {
  t.test('## method - getLatestAuthenticatorStatus', function(t) {
    const ent = new MdsPayloadEntry(FIDO2_PAYLOAD_ENTRY);
    const status = ent.getLatestAuthenticatorStatus();
    t.equal(status, 'FIDO_CERTIFIED_L1');
    t.end();
  });

  t.end();
});
