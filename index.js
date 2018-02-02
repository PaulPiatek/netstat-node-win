'use strict';
const windows_netstat = require(`./build/Release/windows_netstat`);

/**
 * retrieve the connections
 * @return {array}
 */
module.exports = function() {
    return windows_netstat.connections();
};