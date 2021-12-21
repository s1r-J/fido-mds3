fido-mds3
==

Node module for FIDO Alliance Metadata Service v3

## Description

This module helps to access FIDO Alliance Metadata Service (MDS).

(Memo) What is Metadata Service?

> The FIDO Alliance Metadata Service (MDS) is a centralized repository of the Metadata Statement that is used by the relying parties to validate authenticator attestation and prove the genuineness of the device model. 

More detail information about FIDO Alliance Metadata Service is [here](https://fidoalliance.org/metadata/).

How to work:

- Load authenticator information in the manner described below
  - download Metadata Service BLOB file from FIDO Alliance site
  - specify BLOB file's path
  - provide JWT string
- Verify signature(JWS) with FIDO Alliance root certificate
- Find Metadata Statement by an identifier of authenticator(e.g. AAGUID for FIDO2 authenticator).

## Alternatives

- [apowers313/mds-client: FIDO Metadata Service (MDS) Client](https://github.com/apowers313/mds-client)

## Usage

ESM

```js
import FM3 from 'fido-mds3';

const client = new FM3.Builder().build();
client.findByAAGUID('9c835346-796b-4c27-8898-d6032f515cc5').then(data => {
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

CommonJS

```js
const FM3 = require('fido-mds3');

const client = new FM3.Builder().build();
client.findByAAGUID('9c835346-796b-4c27-8898-d6032f515cc5').then(data => {
  console.log(data);
});
```

### Async

```js
import FM3 from 'fido-mds3';

(async () => {
  const builder = new FM3.Builder();
  const client = await builder.buildAsync();
  const data = await client.findByAAGUID('9c835346-796b-4c27-8898-d6032f515cc5');
  console.log(data);
})();

```

## API

Introduce some important APIs.

### Class: Builder

Builder class builds Client class which finds authenticator's information, following config.

#### Builder(\[config\])

- config **FidoMds3Config**

#### build()

- _returns_ **Client**

This method returns the instance of Client class which does not load authenticator's info yet.

#### buildAsync()

- _returns_ **Promise<Client>**

This method returns the instance of Client class which already loads authenticator's info.

### Class: Client

Client class finds authenticator information from metadata service by authenticator model identifier(AAGUID etc.).
#### findByAAGUID(aaguid \[, refresh\])

Find Metadata about FIDO2 authenticator with AAGUID.

- aaguid **string**
  - FIDO2 authenticator AAGUID
- refresh **boolean | FM3RefreshOption**
  - if true force to fetch Metadata BLOB, if false depends on update date
- _returns_ **Promise<MdsPayloadEntry | null>** MetadataBLOBPayloadEntry

#### findByAAID(aaid \[, refresh\])

Find Metadata about FIDO UAF authenticator with AAID.

- aaid **string**
  - FIDO UAF authenticator AAID
- refresh **boolean | FM3RefreshOption**
  - if true force to fetch Metadata BLOB, if false depends on update date
- _returns_ **Promise<MdsPayloadEntry | null>** MetadataBLOBPayloadEntry

#### findByAttestationCertificateKeyIdentifier(attestationCertificateKeyIdentifier \[, refresh\])

Find Metadata about FIDO U2F authenticator with AAID.

- aaid **string**
  - FIDO U2F authenticator AAID
- refresh **boolean | FM3RefreshOption**
  - if true force to fetch Metadata BLOB, if false depends on update date
- _returns_ **Promise<MdsPayloadEntry | null>** MetadataBLOBPayloadEntry

#### findMetadata(identifier \[, refresh\])

Find Metadata about FIDO(FIDO2, FIDO UAF and FIDO U2F) authenticator by identifier(AAGUID, AAID or AttestationCertificateKeyIdentifier).

- identifier **string**
  - FIDO authenticator's identifier
- refresh **boolean | FM3RefreshOption**
  - if true force to fetch Metadata BLOB, if false depends on update date
- _returns_ **Promise<MdsPayloadEntry | null>** MetadataBLOBPayloadEntry

### Class: Accessor

Accessor class executes accessing to metadata service.

#### setRootCertUrl(url)

Set root certificate info.

- url **URL**
  - root certificate's URL

#### fromUrl(url)

Load metadata from metadata service endpoint URL.

- url **URL**
  - metadata service endpoint URL

#### toJsonObject()

Return metadata payload in JSON format.

- _returns_ **JSONObject** metadata payload

## Install

```
npm install fido-mds3
```

## Licence

[MIT](https://opensource.org/licenses/mit-license.php)  

## Author

[s1r-J](https://github.com/s1r-J)