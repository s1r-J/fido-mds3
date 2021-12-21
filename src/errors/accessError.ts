import { FM3BaseError, } from "./baseError";

/**
 * Access error.
 */
class FM3AccessError extends FM3BaseError {
  constructor(message: string) {
    super(message);
    this.name = 'FM3AccessError';
  }
}

export default FM3AccessError;
