class FM3BaseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FM3BaseError';
  }
}

export {
  FM3BaseError,
};