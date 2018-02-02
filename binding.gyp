{
  "targets": [
    {
      "target_name": "windows_netstat",
      'defines': [ 'V8_DEPRECATION_WARNINGS=1' ],
      "sources": [ "src/windows_netstat.cc" ],
      'conditions' : [
        ['OS=="win"', {
          'libraries' : ['ws2_32.lib', 'iphlpapi.lib']
        }]
      ]
    }
  ]
}