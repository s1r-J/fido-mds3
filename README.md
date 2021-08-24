fido-mds3
==

Node module for FIDO Alliance Metadata Service v3

## Description

> The FIDO Alliance Metadata Service (MDS) is a centralized repository of the Metadata Statement that is used by the relying parties to validate authenticator attestation and prove the genuineness of the device model. 

This module helps to access MDS. 

How to work:

- Download Metadata Service BLOB file from FIDO Alliance site.
- Verify signature(JWS) with FIDO Alliance root certificate.
- Find Metadata Statement by an identifier of authenticator(e.g. AAGUID for FIDO2 authenticator).

Detail information about FIDO Alliance Metadata Service is [here](https://fidoalliance.org/metadata/).

## Alternatives

- [apowers313/mds-client: FIDO Metadata Service (MDS) Client](https://github.com/apowers313/mds-client)

## Usage

ESM

```js
import FM3 from 'fido-mds3';

const Client = new FM3.Builder().build();
Client.findByAAGUID('9c835346-796b-4c27-8898-d6032f515cc5').then(data => {
  console.log(data);
});
```

CommonJS

```js
const FM3 = require('fido-mds3');

const Client = new FM3.Builder().build();
Client.findByAAGUID('9c835346-796b-4c27-8898-d6032f515cc5').then(data => {
  console.log(data);
});
// {
//   aaguid: '9c835346-796b-4c27-8898-d6032f515cc5',
//   metadataStatement: {
//     legalHeader: 'https://fidoalliance.org/metadata/metadata-statement-legal-hea
// der/',
//   aaguid: '9c835346-796b-4c27-8898-d6032f515cc5',
//   description: 'Cryptnox FIDO2',
//   authenticatorVersion: 2,
//   protocolFamily: 'fido2',
//   schema: 3,
//       .
//       .
//       .
//   statusReports: [
//     {
//       status: 'FIDO_CERTIFIED_L1',
//       effectiveDate: '2021-01-02',
//       url: 'www.cryptnox.ch',
//       certificateNumber: 'FIDO20020200803001',
//       certificationPolicyVersion: '1.3.7',
//       certificationRequirementsVersion: '1.3.0'
//     }
//   ],
//   timeOfLastStatusChange: '2021-01-02'
// }
```

## API

### Class: Builder

#### Builder(\[config\])

- config 

#### build()

- _returns_ **Client**

### Class: Client

#### findByAAGUID(aaguid \[, refresh\])

Find Metadata about FIDO2 authenticator with AAGUID.

- aaguid **string**
  - FIDO2 authenticator AAGUID
- refresh **boolean**
  - if true force to fetch Metadata BLOB, if false depends on update date
- _returns_ **object** MetadataBLOBPayloadEntry

#### findByAAID(aaid \[, refresh\])

Find Metadata about FIDO UAF authenticator with AAID.

- aaid **string**
  - FIDO UAF authenticator AAID
- refresh **boolean**
  - if true force to fetch Metadata BLOB, if false depends on update date
- _returns_ **object** MetadataBLOBPayloadEntry

#### findByAttestationCertificateKeyIdentifier(attestationCertificateKeyIdentifier \[, refresh\])

Find Metadata about FIDO U2F authenticator with AAID.

- aaid **string**
  - FIDO U2F authenticator AAID
- refresh **boolean**
  - if true force to fetch Metadata BLOB, if false depends on update date
- _returns_ **object** MetadataBLOBPayloadEntry

#### findMetadata(identifier \[, refresh\])

Find Metadata about FIDO(FIDO2, FIDO UAF and FIDO U2F) authenticator by identifier(AAGUID, AAID or AttestationCertificateKeyIdentifier).

- identifier **string**
  - FIDO authenticator's identifier
- refresh **boolean**
  - if true force to fetch Metadata BLOB, if false depends on update date
- _returns_ **object** MetadataBLOBPayloadEntry

## Install

```
npm install fido-mds3
```

## Licence

[MIT](https://opensource.org/licenses/mit-license.php)  

## Author

[s1r-J](https://github.com/s1r-J)