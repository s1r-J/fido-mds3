import { FM3BaseError, } from "./baseError";

/**
 * Inform that metadata is old.
 */
class FM3OldDataError extends FM3BaseError {

  updateAt?: Date;

  constructor(message: string, updateAt?: Date) {
    super(message);
    this.name = 'FM3OldDataError';
    this.updateAt = updateAt;
  }
}

export default FM3OldDataError;
