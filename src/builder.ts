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

    this.config = {
      mdsUrl:  (config && config.mdsUrl) || new URL(defaultConfig.mds.url),
      mdsFile: (config && config.mdsFile) || path.resolve(__dirname, defaultConfig.mds.file),
      payloadFile: (config && config.payloadFile) || path.resolve(__dirname, defaultConfig.payload.file),
      rootUrl: (config && config.rootUrl) || new URL(defaultConfig.root.url),
      rootFile: (config && config.rootFile) || path.resolve(__dirname, defaultConfig.root.file),
    };
  }

  mdsUrl(mdsUrl: URL): Builder {
    if (!mdsUrl) {
      throw new FM3InvalidParameterError('"mdsUrl" is empty.');
    }
    this.config.mdsUrl = mdsUrl;

    return this;
  }

  mdsFile(mdsFile: string): Builder {
    if (!mdsFile) {
      throw new FM3InvalidParameterError('"mdsFile" is empty.');
    }
    this.config.mdsFile = mdsFile;

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

    return this;
  }

  rootFile(rootFile: string): Builder {
    if (!rootFile) {
      throw new FM3InvalidParameterError('"rootFile" is empty.');
    }
    this.config.rootFile = rootFile;

    return this;
  }

  build(): Client {
    return new Client(this.config);
  }
}

export default Builder;