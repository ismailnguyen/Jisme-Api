const axios = require('axios');

exports.findLocationFromIp = async function (ip) {
    try {
        const ipInfo = await axios.get(`https://ipapi.co/${ip}/json`);
        return ipInfo.data;
    } catch (error) {
        return null;
    }
}