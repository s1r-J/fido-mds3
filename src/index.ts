import FM3InvalidParameterError from './errors/invalidParameterError'
import FM3SettingError from './errors/settingError';
import Client from './client';
import Builder from './builder';

export {
  FidoMds3Config,
  FM3MetadataStatement,
  FM3BiometricStatusReport,
  FM3AuthenticatorStatus,
  FM3StatusReport,
  FM3MetadataBLOBPayloadEntry,
} from './type';

const FidoMds3 = {
  Builder,
  Client,
  FM3InvalidParameterError,
  FM3SettingError,
};

export default FidoMds3;