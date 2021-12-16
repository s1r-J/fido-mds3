import dayjs from 'dayjs';
import fs from 'fs';

import {
  FM3FindOption,
  FidoMds3Config,
  FM3MetadataBLOBPayloadEntry,
} from './type';
import MdsPayloadEntry from './models/mdsPayloadEntry';
import FM3InvalidParameterError from './errors/invalidParameterError';
import FM3SettingError from './errors/settingError';
import FM3OldDataError from './errors/oldDataError';
import Accessor from './accessor';

class Client {

  private config: FidoMds3Config;
  updatedAt?: Date;
  legalHeader? : string;
  no?: number;
  nextUpdateAt?: Date;
  entries?: FM3MetadataBLOBPayloadEntry[];

  constructor(config: FidoMds3Config) {
    this.config = config;                                                                                                                                                                                                                                                                         
  }

  static async create(config: FidoMds3Config): Promise<Client> {
    const client = new Client(config);
    await client.load();
    return client;
  }

  async refresh(): Promise<void> {
    await this.load();
  }

  private format(payloadJSON: any) {
    const entriesJSONArray = payloadJSON['entries'];
    this.entries = [];
    for (let ent of entriesJSONArray) {
      this.entries.push(ent as FM3MetadataBLOBPayloadEntry); // XXX danger
    }

    this.updatedAt = dayjs().toDate();
    this.legalHeader = payloadJSON['legalHeader'];
    this.no = payloadJSON['no'];
    this.nextUpdateAt = dayjs(payloadJSON['nextUpdate'], 'YYYY-MM-DD').toDate();
  }

  private async load() {

    // set root certificate
    Accessor.detachRootCert();
    switch (this.config.accessRootCertificate) {
      case 'url':
        await Accessor.setRootCertUrl(this.config.rootUrl);
        break;
      case 'file':
        await Accessor.setRootCertFile(this.config.rootFile);
        break;
      case 'pem':
        if (!this.config.rootPem) {
          throw new FM3SettingError('Please set root certificate pem.');
        }
        Accessor.setRootCertPem(this.config.rootPem);
        break;
      default:
        throw new FM3SettingError('Please set how to access root certificate.');
    }

    // set mds data
    switch (this.config.accessMds) {
      case 'url':
        await Accessor.fromUrl(this.config.mdsUrl);
        break;
      case 'file':
        const jwtStr = fs.readFileSync(this.config.mdsFile, 'utf-8');
        await Accessor.fromJwt(jwtStr);
        break;
      case 'jwt':
        if (!this.config.mdsJwt) {
          throw new FM3SettingError('Please set mds jwt.');
        }
        await Accessor.fromJwt(this.config.mdsJwt);
        break;
      default:
        throw new FM3SettingError('Please set how to access MDS.');
    }

    await Accessor.toFile(this.config.payloadFile);  // deprecated
    const data = Accessor.toJsonObject();
    this.format(data);
  }

  private async judgeRefresh(refresh?: boolean | FM3FindOption) {
    let option: FM3FindOption = 'needed';
    if (typeof refresh === 'boolean') {
      option = refresh ? 'force' : 'needed';
    } else if (refresh != null) {
      option = refresh;
    }

    if (option === 'force') {
      await this.refresh();
    } else if (option === 'needed' && (!this.entries || (this.nextUpdateAt && dayjs(this.nextUpdateAt).isBefore(dayjs())))) {
      await this.refresh();
    } else if (option === 'error' && (!this.entries || (this.nextUpdateAt && dayjs(this.nextUpdateAt).isBefore(dayjs())))) {
      throw new FM3OldDataError(`Metadata is old. Update at ${this.nextUpdateAt && dayjs(this.nextUpdateAt).toISOString()}`, this.nextUpdateAt);
    }
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
  async findByAAGUID(aaguid: string, refresh?: boolean | FM3FindOption): Promise<FM3MetadataBLOBPayloadEntry | null> {

    if (!aaguid) {
      throw new FM3InvalidParameterError('"aaguid" is empty.');
    }

    await this.judgeRefresh(refresh);
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

  async findModelByAAGUID(aaguid: string, refresh?: boolean | FM3FindOption): Promise<MdsPayloadEntry | null> {
    const entry = await this.findByAAGUID(aaguid, refresh);
    if (entry) {
      return new MdsPayloadEntry(entry);
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
  async findByAAID(aaid: string, refresh?: boolean | FM3FindOption): Promise<FM3MetadataBLOBPayloadEntry | null> {

    if (!aaid) {
      throw new FM3InvalidParameterError('"aaid" is empty.');
    }

    await this.judgeRefresh(refresh);
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

  async findModelByAAID(aaid: string, refresh?: boolean | FM3FindOption): Promise<MdsPayloadEntry | null> {
    const entry = await this.findByAAID(aaid, refresh);
    if (entry) {
      return new MdsPayloadEntry(entry);
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
  async findByAttestationCertificateKeyIdentifier(attestationCertificateKeyIdentifier: string, refresh?: boolean | FM3FindOption): Promise<FM3MetadataBLOBPayloadEntry | null> {

    if (!attestationCertificateKeyIdentifier) {
      throw new FM3InvalidParameterError('"attestationCertificateKeyIdentifiers" is empty.');
    }

    await this.judgeRefresh(refresh);
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

  async findModelByAttestationCertificateKeyIdentifier(attestationCertificateKeyIdentifier: string, refresh?: boolean | FM3FindOption): Promise<MdsPayloadEntry | null> {
    const entry = await this.findByAttestationCertificateKeyIdentifier(attestationCertificateKeyIdentifier, refresh);
    if (entry) {
      return new MdsPayloadEntry(entry);
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
  async findMetadata(identifier: string, refresh?: boolean | FM3FindOption): Promise<FM3MetadataBLOBPayloadEntry | null> {
    const findFunctions = [this.findByAAGUID, this.findByAAID, this.findByAttestationCertificateKeyIdentifier];
    let isAlreadyRefresh = false;
    for (let func of findFunctions) {
      let option: FM3FindOption;
      switch (refresh) {
        case 'error':
          option = 'error';
          break;
        case 'force':
        case true:
          option = isAlreadyRefresh ? 'needed' : 'force';
          break;
        case 'needed':
        case false:
        default:
          option = 'needed';
      }
      const ent = await func.call(this, identifier, option);
      if (ent) {
        return ent;
      }

      isAlreadyRefresh = true;
    }

    return null;
  }

  async findMetadataModel(identifier: string, refresh?: boolean | FM3FindOption): Promise<MdsPayloadEntry | null> {
    const entry = await this.findMetadata(identifier, refresh);
    if (entry) {
      return new MdsPayloadEntry(entry);
    }

    return null;
  }

}

export default Client;
