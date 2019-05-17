class DuplicateKeyError extends Error {
  constructor(message, originalError) {
    super(message);
    this.originalError = originalError;
    this.statusCode = 409; // 409 Conflict
  }
}

module.exports = {
  DuplicateKeyError,
};
