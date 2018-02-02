'use strict';
const binding = require(`./build/Release/windows_netstat`);
console.log('binding.connections() =', binding.connections());