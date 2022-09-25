function Exception(reason, error, code) {
    this.name = reason || 'Error';
    this.message = error && error.message ? error.message : error;
    this.code = code || 500;

	this.toJSON = function () {
		console.error('ERROR: ' + this.name + '(' + this.message + ')');

		return {
			status: this.code,
			data: {
				error: {
					reason: this.name,
					message: this.message
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
  
  