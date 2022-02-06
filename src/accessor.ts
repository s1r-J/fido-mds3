import fs from 'fs';
import path from 'path';
import axios from 'axios';
import base64url from 'base64url';
import {
  parse,
} from 'comment-json';
import dayjs from 'dayjs';
import rs from 'jsrsasign';
import FM3AccessError from './errors/accessError';

/**
 * Accessor class executes accessing to metadata service.
 * 
 */
class Accessor {
  private static payloadData?: string;
  private static rootCert?: rs.X509;
  private static alg?: string;

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
    const certificate = new rs.X509();
    certificate.readCertPEM(pem);
    Accessor.rootCert = certificate;
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
    const certificate = new rs.X509();
    certificate.readCertPEM(pem);
    Accessor.rootCert = certificate;
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
      const certificate = new rs.X509();
      certificate.readCertPEM(pem);
      Accessor.rootCert = certificate;
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

    const certPEMs = [];
    const rsCerts = [];
    let crlSNs: string[] = [];
    for (const x5c of headerJSON['x5c']) {
      const certPemString = ['-----BEGIN CERTIFICATE-----', x5c, '-----END CERTIFICATE-----'].join('\n');
      certPEMs.push(certPemString);

      const rsCertificate = new rs.X509();
      rsCertificate.readCertPEM(certPemString);
      rsCerts.push(rsCertificate);
      
      const crlUris = rsCertificate.getExtCRLDistributionPointsURI() || [];
      const snInArray = await Promise.all(crlUris.map(async (uri) => {
        const res = await axios.get(uri, { responseType: 'arraybuffer' });
        const crlPEM = ['-----BEGIN X509 CRL-----', Buffer.from(res.data).toString('base64'), '-----END X509 CRL-----'].join('\n');
        const crl = new rs.X509CRL(crlPEM);
        const revSNs = crl.getRevCertArray().map((revCert) => {
          return revCert.sn.hex;
        }) || [];

        return revSNs;
      })) || [[]];

      crlSNs = [
        ...crlSNs,
        ...snInArray.flat(),
      ];
    }

    let rootCert = Accessor.rootCert;
    if (!rootCert) {
      // root certificate is not set
      const configJson = fs.readFileSync(path.resolve(__dirname, '../config/config.json'), 'utf-8');
      const defaultConfig = parse(configJson);
      try {
        // use file in this module
        const bstr = fs.readFileSync(path.resolve(__dirname, defaultConfig.root.file)).toString('base64');
        const pem = ['-----BEGIN CERTIFICATE-----', bstr, '-----END CERTIFICATE-----'].join('\n');
        const cert = new rs.X509();
        cert.readCertPEM(pem);
        if (dayjs().isAfter(dayjs(rs.zulutomsec(cert.getNotBefore()))) && dayjs().isBefore(dayjs(rs.zulutomsec(cert.getNotAfter())))) {
          rootCert = cert;
        } else {
          throw new Error('Root certificate file in this module is not valid.');
        }
      } catch (err) {
        // use certificate in the internet
        const buf = await Accessor._requestRootCertificate(new URL(defaultConfig.root.url));
        const bstr = buf.toString('base64');
        const pem = ['-----BEGIN CERTIFICATE-----', bstr, '-----END CERTIFICATE-----'].join('\n');
        const cert = new rs.X509();;
        cert.readCertPEM(pem);
        rootCert = cert;
        fs.writeFileSync(defaultConfig.root.file, buf);
      }
    }
    rsCerts.push(rootCert);
    certPEMs.push(['-----BEGIN CERTIFICATE-----', Buffer.from(rootCert.hex, 'hex').toString('base64'), '-----END CERTIFICATE-----'].join('\n'))

    const hasRevokedCert = rsCerts.some((c) => {
      const sn = c.getSerialNumberHex();
      return crlSNs.includes(sn);
    });
    if (hasRevokedCert) {
      throw new FM3AccessError('Revoked certificate is included.');
    }

    let isValidChain = true;
    for (let i = 0; i < rsCerts.length - 1; i++) {
      const cert = rsCerts[i];
      const certStruct = rs.ASN1HEX.getTLVbyList(cert.hex, 0, [0]);
      if (certStruct == null) {
        isValidChain = false;
        break;
      }
      const algorithm = cert.getSignatureAlgorithmField();
      const signatureHex = cert.getSignatureValueHex()

      // 上位の証明書に対して検証をおこなう
      const signature = new rs.KJUR.crypto.Signature({alg: algorithm});
      const upperCertPEM = certPEMs[i + 1];
      signature.init(upperCertPEM);
      signature.updateHex(certStruct);
      isValidChain = isValidChain && signature.verify(signatureHex); // チェーン全ての証明書が正当かを確認
    }
    if (!isValidChain) {
      throw new FM3AccessError('Certificate chain cannot be verified.');
    }

    // verify signature
    const alg = headerJSON['alg'];
    const isValid = rs.KJUR.jws.JWS.verifyJWT(blobJwt, certPEMs[0], {alg: [alg]});
    if (!isValid) {
      throw new FM3AccessError('JWS cannot be verified.');
    }
    Accessor.alg = alg;

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
