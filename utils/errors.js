'use strict';

function Exception(message, error, code) {
    this.message = message || 'Error';
    this.reason = error && error.message ? error.message : error;
    this.code = code || (error && error.code ? error.code : 500);

	this.toJSON = function () {
		console.error('ERROR: ' + this.message + ' (' + this.reason + ')');

		return {
			status: this.code,
			data: {
				error: {
					message: this.message,
					reason: this.reason
				}
			}
		}
	}
}

exports.throwError = function(exception) {
  if (exception && typeof exception.toJSON === 'function') {
    return exception.toJSON();
  }
  return {
    status: exception && exception.code ? exception.code : 500,
    data: {
      error: {
        message: exception && exception.message || 'Error',
        reason: (exception && exception.reason) || (exception && exception.message) || 'Unexpected error'
      }
    }
  };
}

exports.generateError = function(reason, message, code) {
	return new Exception(reason, message, code);
}
