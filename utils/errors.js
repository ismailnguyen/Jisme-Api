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
  return exception.toJSON();
}

exports.generateError = function(reason, message, code) {
	return new Exception(reason, message, code);
}
