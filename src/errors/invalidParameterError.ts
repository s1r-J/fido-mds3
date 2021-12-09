import { FM3BaseError, } from "./baseError";

/**
 * Parameter is invalid.
 */
class FM3InvalidParameterError extends FM3BaseError {
  constructor(message: string) {
    super(message);
    this.name = 'FM3InvalidParameterError';
  }
}

export default FM3InvalidParameterError;
