exports.throwError = function({ reason, message, code }) {
	console.error('ERROR: ' + message + '(' + reason + ')');
  
	return {
		status: code || 500,
		data: {
			error: {
				message: message,
				reason: reason ? reason.message : 'Error'
			}
		}
	}
}

exports.generateError = function(reason, message, code) {
	return {
		reason: reason,
		message: message,
		errorCode: code
	};
  }
  
  