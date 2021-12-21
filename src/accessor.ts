import fs from 'fs';
import path from 'path';
import axios from 'axios';
import base64url from 'base64url';
import {
  parse,
} from 'comment-json';
import dayjs from 'dayjs';
import rs from 'jsrsasign';
import {
  pki,
} from 'node-forge';
import FM3AccessError from './errors/accessError';

/**
 * Accessor class executes accessing to metadata service.
 * 
 */
class Accessor {
  private static payloadData?: string;
  private static rootCert?: pki.Certificate;

  private constructor() {
  }

  /**
   * This method is expected to use in this class.
   * 
   * @param url root certificate download endpoint
   * @returns root certificate's buffer
   */
  static async _requestRootCertificate(url: URL): Promise<Buffer> {
    const response = await axios.get(url.toString(), { responseType : 'arraybuffer', });
    const data = response.data;
    if (!(data instanceof Buffer)) {
      throw new FM3AccessError('Response data is not binary.');
    }

    return data;
  }

  /**
   * Detach root certificate info.
   */
  static detachRootCert(): void {
    Accessor.rootCert = undefined;
  }

  /**
   * Set root certificate info.
   * 
   * @param pem PEM format certificate
   */
  static setRootCertPem(pem: string): void {
    Accessor.rootCert = pki.certificateFromPem(pem);
  }

  /**
   * Set root certificate info.
   * 
   * @param filePath DER format certificate's file path
   */
  static async setRootCertFile(filePath: string): Promise<void> {
    const buf = fs.readFileSync(filePath);
    const bstr = buf.toString('base64');
    const pem = ['-----BEGIN CERTIFICATE-----', bstr, '-----END CERTIFICATE-----'].join('\n');
    Accessor.rootCert = pki.certificateFromPem(pem);
  }

  /**
   * Set root certificate info.
   * 
   * @param url certificate's URL
   */
  static async setRootCertUrl(url: URL): Promise<void> {
    try {
      const buf = await Accessor._requestRootCertificate(url);
      const bstr = buf.toString('base64');
      const pem = ['-----BEGIN CERTIFICATE-----', bstr, '-----END CERTIFICATE-----'].join('\n');
      Accessor.rootCert = pki.certificateFromPem(pem);
    } catch (err) {
      if (axios.isAxiosError(err) && err.response) {
        throw new FM3AccessError(`Request has error. Status code: ${err.response.status}`);
      }

      throw err;
    }
  }

  /**
   * Load metadata.
   * 
   * @param blobJwt JWT format metadata
   */
  static async fromJwt(blobJwt: string): Promise<void> {
    const [header, payload, signature] = blobJwt.split('.');
    if (!header || !payload || !signature) {
      throw new FM3AccessError('Blob JWT is wrong format.');
    }

    const headerJSON = JSON.parse(base64url.decode(header));
    const x5cArray = headerJSON['x5c'];
    const pkiCerts = []
    const certKeys = [];
    for (const x5c of x5cArray) {
      const certPemString = ['-----BEGIN CERTIFICATE-----', x5c, '-----END CERTIFICATE-----'].join('\n');
      // collect certificate
      pkiCerts.push(pki.certificateFromPem(certPemString));

      // collect public key
      const publicKey = rs.X509.getPublicKeyFromCertPEM(certPemString);
      certKeys.push(rs.KEYUTIL.getPEM(publicKey));
    }

    // verify signature
    const alg = headerJSON['alg'];
    const isValid = rs.KJUR.jws.JWS.verifyJWT(blobJwt, certKeys[0], {alg: [alg]});
    if (!isValid) {
      throw new FM3AccessError('JWS cannot be verified.');
    }

    // verify certificate chain
    let rootCert = Accessor.rootCert;
    if (!rootCert) {
      // root certificate is not set
      const configJson = fs.readFileSync(path.resolve(__dirname, '../config/config.json'), 'utf-8');
      const defaultConfig = parse(configJson);
      try {
        // use file in this module
        const bstr = fs.readFileSync(path.resolve(__dirname, defaultConfig.root.file)).toString('base64');
        const pem = ['-----BEGIN CERTIFICATE-----', bstr, '-----END CERTIFICATE-----'].join('\n');
        const cert = pki.certificateFromPem(pem);
        if (dayjs().isAfter(cert.validity.notBefore) && dayjs().isBefore(cert.validity.notAfter)) {
          rootCert = cert;
        } else {
          throw new Error('Root certificate file int this module is not valid.');
        }
      } catch (err) {
        // use certificate in the internet
        const buf = await Accessor._requestRootCertificate(new URL(defaultConfig.root.url));
        const bstr = buf.toString('base64');
        const pem = ['-----BEGIN CERTIFICATE-----', bstr, '-----END CERTIFICATE-----'].join('\n');
        rootCert = pki.certificateFromPem(pem);
        fs.writeFileSync(defaultConfig.root.file, buf);
      }
    }

    const caStore = pki.createCaStore([ ...pkiCerts, rootCert ]);
    const result = pki.verifyCertificateChain(caStore, [ rootCert ]);  
    if (!result) {
      throw new FM3AccessError('Certificate chain cannot be verified.');
    }

    // decode payload
    const payloadString = base64url.decode(payload);
    Accessor.payloadData = payloadString;
  }

  /**
   * Load metadata.
   * 
   * @param filePath JWT format file's path
   */
  static async fromFile(filePath: string): Promise<void> {
    const jwtStr = fs.readFileSync(filePath, 'utf-8');
    await Accessor.fromJwt(jwtStr);
  }

  /**
   * Load metadata.
   * 
   * @param url metadata's endpoint URL
   */
  static async fromUrl(url: URL): Promise<void> {
    const mdsResponse = await axios.get(url.toString());
    await Accessor.fromJwt(mdsResponse.data);
  }

  /**
   * Return metadata payload.
   * 
   * @returns metadata in JSON Object
   */
  static toJsonObject(): any {
    if (!Accessor.payloadData) {
      throw new FM3AccessError('Payload Data is not found.');
    }

    return JSON.parse(Accessor.payloadData);
  }

  /**
   * Return metadata payload.
   * 
   * @param filePath write metadata payload in this file
   */
  static async toFile(filePath: any): Promise<void> {
    if (!Accessor.payloadData) {
      throw new FM3AccessError('Payload Data is not found.');
    }

    fs.writeFileSync(filePath, Accessor.payloadData);
  }
}

export default Accessor;
