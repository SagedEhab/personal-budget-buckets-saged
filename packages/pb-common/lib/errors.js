// One error type for the whole application. Controllers throw ApiError and the
// central error handler (lib/http.js) turns it into { error: { code, message, details } }.
class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

const errors = {
  badRequest: (message, details) => new ApiError(400, 'VALIDATION_ERROR', message, details),
  unauthorized: (message = 'Authentication is required.') => new ApiError(401, 'UNAUTHENTICATED', message),
  forbidden: (message = 'You do not have permission to perform this action.') => new ApiError(403, 'FORBIDDEN', message),
  notFound: (what = 'Resource') => new ApiError(404, 'NOT_FOUND', `${what} not found.`),
  conflict: (code, message, details) => new ApiError(409, code, message, details),
  unprocessable: (code, message, details) => new ApiError(422, code, message, details),
  unavailable: (code, message) => new ApiError(503, code, message)
};

module.exports = { ApiError, errors };
