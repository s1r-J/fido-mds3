import fs from 'fs';
import axios from 'axios';
import base64url from 'base64url';
import rs from 'jsrsasign';
import moment from 'moment';
import {
  pki,
} from 'node-forge';

import {
  FidoMds3Config,
  FM3MetadataBLOBPayloadEntry,
} from './type';
import FM3InvalidParameterError from './errors/invalidParameterError';
import FM3SettingError from './errors/settingError';

class Client {

  private config: FidoMds3Config;
  legalHeader? : string;
  updatedAt?: Date;
  no?: number;
  nextUpdateAt?: Date;
  entries?: FM3MetadataBLOBPayloadEntry[];

  constructor(config: FidoMds3Config) {
    this.config = config;
    this.load();
  }

  async refresh() {
    const mdsFileResponse = await axios.get(this.config.mdsUrl.toString());
    fs.writeFileSync(this.config.mdsFile, mdsFileResponse.data, 'utf-8');

    this.verifyCertification(mdsFileResponse.data);

    this.parse(mdsFileResponse.data);
  }

  private async verifyCertification(blobJwt: string) {
    const [header, payload, signature] = blobJwt.split('.');
    if (!header || !payload || !signature) {
      throw new FM3SettingError('Blob file does not have three dot.');
    }

    const headerJSON = JSON.parse(base64url.decode(header));
    const x5cArray = headerJSON['x5c'];
    const certKeysPki = []
    const certKeys = [];
    for (const x5c of x5cArray) {
      const certKeyString = ['-----BEGIN CERTIFICATE-----', x5c, "-----END CERTIFICATE-----"].join('\n');
      certKeysPki.push(pki.certificateFromPem(certKeyString));
      const certKey = rs.X509.getPublicKeyFromCertPEM(certKeyString);
      const certKeyPem = rs.KEYUTIL.getPEM(certKey);
      certKeys.push(certKeyPem);
    }

    const alg = headerJSON['alg'];
    const isValid = rs.KJUR.jws.JWS.verifyJWT(blobJwt, certKeys[0], {alg: [alg]});
    if (!isValid) {
      throw new FM3SettingError('JWS cannot be verified.');
    }

    // verify certificate chain
    // [ssl - Using node.js to verify a X509 certificate with CA cert - Stack Overflow](https://stackoverflow.com/questions/48377731/using-node-js-to-verify-a-x509-certificate-with-ca-cert)
    const rootCrtResponse = await axios.get(this.config.rootUrl.toString());
    fs.writeFileSync(this.config.rootFile, rootCrtResponse.data, 'utf-8');
    const cert = pki.certificateFromPem(rootCrtResponse.data);
    const caStore = pki.createCaStore([ ...certKeysPki, cert ]);
    const result = pki.verifyCertificateChain(caStore, [ cert ]);
    if (!result) {
      throw new FM3SettingError('Certificate chain cannot be verified.');
    }
  }

  private async parse(blobJwt: string) {
    const [, payload,] = blobJwt.split('.');
    const payloadString = base64url.decode(payload);
    const payloadJSON = JSON.parse(payloadString);
    fs.writeFileSync(this.config.payloadFile, payloadString, 'utf-8');

    this.format(payloadJSON);
    
    this.updatedAt = moment().toDate();
  }

  private format(payloadJSON: any) {
    this.legalHeader = payloadJSON['legalHeader'];
    this.no = payloadJSON['no'];
    this.nextUpdateAt = moment.utc(payloadJSON['nextUpdate'], 'YYYY-MM-DD').toDate();
    const entriesJSONArray = payloadJSON['entries'];

    this.entries = [];
    for (let ent of entriesJSONArray) {
      this.entries.push(ent as FM3MetadataBLOBPayloadEntry); // XXX danger
    }
  }

  private async load() {
    const payloadJSON = JSON.parse(fs.readFileSync(this.config.payloadFile, 'utf-8'));
    this.format(payloadJSON);
  }

  /**
   * Find FIDO2 authenticator by AAGUID.
   * 
   * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
   * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
   * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.<br/>
   * 
   * @param aaguid FIDO2 authenticator AAGUID
   * @param refresh if true force to fetch Metadata BLOB, if false depends on update date
   * @returns Metadata entry if not find return null
   */
  async findByAAGUID(aaguid: string, refresh?: boolean): Promise<FM3MetadataBLOBPayloadEntry | null> {

    if (!aaguid) {
      throw new FM3InvalidParameterError('"aaguid" is empty.');
    }

    if (refresh || !this.entries || (this.nextUpdateAt && moment(this.nextUpdateAt).isBefore(moment()))) {
      await this.refresh();
    }
    if (!this.entries) {
      throw new FM3SettingError('Metadata cannot be fetched.');
    }

    for (let ent of this.entries) {
      if (ent.aaguid === aaguid) {
        return ent;
      } else {
        let ms = ent.metadataStatement;
        if (ms && ms.aaguid === aaguid) {
          return ent;
        }
      }
    }

    return null;
  }

  /**
   * Find FIDO UAF authenticator by AAID.
   * 
   * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
   * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
   * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.<br/>
   * 
   * @param aaid FIDO UAF authenticator AAID
   * @param refresh if true force to fetch Metadata BLOB, if false depends on update date.
   * @returns Metadata entry if not find return null
   */
  async findByAAID(aaid: string, refresh?: boolean): Promise<FM3MetadataBLOBPayloadEntry | null> {

    if (!aaid) {
      throw new FM3InvalidParameterError('"aaid" is empty.');
    }

    if (refresh || !this.entries || (this.nextUpdateAt && moment(this.nextUpdateAt).isBefore(moment()))) {
      await this.refresh();
    }
    if (!this.entries) {
      throw new FM3SettingError('Metadata cannot be fetched.');
    }

    for (let ent of this.entries) {
      if (ent.aaid === aaid) {
        return ent;
      } else {
        let ms = ent.metadataStatement;
        if (ms && ms.aaid === aaid) {
          return ent;
        }
      }
    }

    return null;
  }

  /**
   * Find FIDO U2F authenticator by AttestationCertificateKeyIdentifier.
   * 
   * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
   * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
   * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.<br/>
   * 
   * @param attestationCertificateKeyIdentifier FIDO U2F authenticator AttestationCertificateKeyIdentifier
   * @param refresh if true force to fetch Metadata BLOB, if false depends on update date
   * @returns Metadata entry if not find return null
   */
  async findByAttestationCertificateKeyIdentifier(attestationCertificateKeyIdentifier: string, refresh?: boolean): Promise<FM3MetadataBLOBPayloadEntry | null> {

    if (!attestationCertificateKeyIdentifier) {
      throw new FM3InvalidParameterError('"attestationCertificateKeyIdentifiers" is empty.');
    }

    if (refresh || !this.entries || (this.nextUpdateAt && moment(this.nextUpdateAt).isBefore(moment()))) {
      await this.refresh();
    }
    if (!this.entries) {
      throw new FM3SettingError('Metadata cannot be fetched.');
    }

    for (let ent of this.entries) {
      if (!ent.attestationCertificateKeyIdentifiers) {
        continue;
      }

      if (ent.attestationCertificateKeyIdentifiers.some(aki => aki === attestationCertificateKeyIdentifier)) {
        return ent;
      } else {
        let ms = ent.metadataStatement;
        if (ms && ms.attestationCertificateKeyIdentifiers && ms.attestationCertificateKeyIdentifiers.some(aki => aki === attestationCertificateKeyIdentifier)) {
          return ent;
        }
      }
    }

    return null;
  }

  /**
   * Find FIDO(FIDO2, FIDO UAF and FIDO U2F) authenticator.
   * 
   * @param identifier AAGUID, AAID or AttestationCertificateKeyIdentifier
   * @param refresh if true force to fetch Metadata BLOB, if false depends on update date
   * @returns Metadata entry if not find return null
   */
  async findMetadata(identifier: string, refresh?: boolean): Promise<FM3MetadataBLOBPayloadEntry | null> {

    const findFunctions = [this.findByAAGUID, this.findByAAID, this.findByAttestationCertificateKeyIdentifier];
    let isAlreadyRefresh = false;
    for (let func of findFunctions) {
      let ent = await func.call(this, identifier, refresh && !isAlreadyRefresh);
      if (ent) {
        return ent;
      }

      isAlreadyRefresh = true;
    }

    return null;
  }

}

export default Client;
