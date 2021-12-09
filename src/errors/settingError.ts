import { FM3BaseError, } from "./baseError";

/**
 * Setting(default configure, file download, file save or certification validation) is invalid.
 */
class FM3SettingError extends FM3BaseError {
  constructor(message: string) {
    super(message);
    this.name = 'FM3SettingError';
  }
}

export default FM3SettingError;
