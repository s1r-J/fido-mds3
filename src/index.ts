import FM3AccessError from './errors/accessError';
import FM3InvalidParameterError from './errors/invalidParameterError'
import FM3OldDataError from './errors/oldDataError';
import FM3SettingError from './errors/settingError';
import Accessor from './accessor';
import Builder from './builder';
import Client from './client';

export {
  FidoMds3Config,
  FM3MetadataStatement,
  FM3BiometricStatusReport,
  FM3AuthenticatorStatus,
  FM3StatusReport,
  FM3MetadataBLOBPayloadEntry,
} from './type';

const FidoMds3 = {
  Accessor,
  Builder,
  Client,
  FM3AccessError,
  FM3InvalidParameterError,
  FM3OldDataError,
  FM3SettingError,
};

export default FidoMds3;