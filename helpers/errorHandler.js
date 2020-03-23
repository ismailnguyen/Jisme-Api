// Generic error handler used by all endpoints.
exports.handleError = function(response, reason, message, code)
{
  console.error('ERROR: ' + message + '(' + reason + ')');

  return response
		.status(code || 500)
		.json(
			{
				"error": {
					"message": message,
					"reason": reason
				}
			});
}
