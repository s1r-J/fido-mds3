import fs from 'fs';
import path from 'path';
import {
  parse,
} from 'comment-json';

import {
  FidoMds3Config,
} from './type';
import FM3InvalidParameterError from './errors/invalidParameterError';
import Client from './client';

class Builder {

  private config: FidoMds3Config;

  constructor(config?: Partial<FidoMds3Config>) {
    const configJson = fs.readFileSync(path.resolve(__dirname, '../config/config.json'), 'utf-8');
    const defaultConfig = parse(configJson);

    if (config && !config.accessMds) {
      if (config.mdsUrl && !config.mdsFile && !config.mdsJwt) {
        config.accessMds = 'url';
      } else if (!config.mdsUrl && config.mdsFile && !config.mdsJwt) {
        config.accessMds = 'file';
      } else if (!config.mdsUrl && !config.mdsFile && config.mdsJwt) {
        config.accessMds = 'jwt';
      }
    }

    if (config && !config.accessRootCertificate) {
      if (config.rootUrl && !config.rootFile && !config.rootPem) {
        config.accessRootCertificate = 'url';
      } else if (!config.rootUrl && config.rootFile && !config.rootPem) {
        config.accessRootCertificate = 'file'
      } else if (!config.rootUrl && !config.rootFile && config.rootPem) {
        config.accessRootCertificate = 'pem'
      }
    }

    this.config = {
      mdsUrl:  (config && config.mdsUrl) || new URL(defaultConfig.mds.url),
      mdsFile: (config && config.mdsFile) || path.resolve(__dirname, defaultConfig.mds.file),
      mdsJwt: (config && config.mdsJwt) || undefined,
      payloadFile: (config && config.payloadFile) || path.resolve(__dirname, defaultConfig.payload.file),
      rootUrl: (config && config.rootUrl) || new URL(defaultConfig.root.url),
      rootFile: (config && config.rootFile) || path.resolve(__dirname, defaultConfig.root.file),
      rootPem: (config && config.rootPem) || undefined,

      accessMds: (config && config.accessMds) || defaultConfig.mds.access,
      accessRootCertificate: (config && config.accessRootCertificate) || defaultConfig.root.access,
    };
  }

  mdsUrl(mdsUrl: URL): Builder {
    if (!mdsUrl) {
      throw new FM3InvalidParameterError('"mdsUrl" is empty.');
    }
    this.config.mdsUrl = mdsUrl;
    this.config.accessMds = 'url';

    return this;
  }

  mdsFile(mdsFile: string): Builder {
    if (!mdsFile) {
      throw new FM3InvalidParameterError('"mdsFile" is empty.');
    }
    this.config.mdsFile = mdsFile;
    this.config.accessMds = 'file';

    return this;
  }

  mdsJwt(mdsJwt: string): Builder {
    if (!mdsJwt) {
      throw new FM3InvalidParameterError('"mdsJwt" is empty.');
    }
    this.config.mdsJwt = mdsJwt;
    this.config.accessMds = 'jwt';

    return this;
  }

  payloadFile(payloadFile: string): Builder {
    if (!payloadFile) {
      throw new FM3InvalidParameterError('"payloadFile" is empty.');
    }
    this.config.payloadFile = payloadFile;

    return this;
  }

  rootUrl(rootUrl: URL): Builder {
    if (!rootUrl) {
      throw new FM3InvalidParameterError('"rootUrl" is empty.');
    }
    this.config.rootUrl = rootUrl;
    this.config.accessRootCertificate = 'url';

    return this;
  }

  rootFile(rootFile: string): Builder {
    if (!rootFile) {
      throw new FM3InvalidParameterError('"rootFile" is empty.');
    }
    this.config.rootFile = rootFile;
    this.config.accessRootCertificate = 'file';

    return this;
  }

  rootPem(rootPem: string): Builder {
    if (!rootPem) {
      throw new FM3InvalidParameterError('"rootPem" is empty.');
    }
    this.config.rootPem = rootPem;
    this.config.accessRootCertificate = 'pem';

    return this;
  }

  build(): Client {
    return new Client(this.config);
  }

  async buildAsync(): Promise<Client> {
    return await Client.create(this.config);
  }
}

export default Builder;