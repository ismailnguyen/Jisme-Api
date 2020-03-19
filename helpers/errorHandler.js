// Generic error handler used by all endpoints.
exports.handleError = function(res, reason, message, code)
{
  console.log('ERROR: ' + message + '(' + reason + ')');
  res
  .status(code || 500)
  .json(
	{
		"error": {
			"message": message,
			"reason": reason
		}
	});
}
