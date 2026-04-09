# Wireshark dissector for the [Cubesat Space Protocol](https://github.com/libcsp/libcsp)

This dissector is based on [daniestevez](https://github.com/daniestevez)'s dissector from [csp-tools](https://github.com/daniestevez/csp-tools).
It is modularized such that it is easy to add other interfaces (in this case raw Ethernet)

## Supported Features

 - [x] Ethernet Fragmentation Protocol (for raw Ethernet interface)
     - [ ] Fragment Reassembly (Currently only supports small CSP packets that will not get fragmented)
 - [x] CSP Header fields
 - [x] CRC32 Checksum validation
 - [ ] HMAC awareness
 - [x] RDP Header fields
 - [ ] CSP Management Protocol (CMP)
 - [ ] Other interfaces
    - [ ] CSP over UDP
    - [ ] ZeroMQ
    - [ ] CAN
    - [ ] I2C and UART (Not sure if those are possible to inspect in Wireshark)

## Usage

Copy or symlink all lua files to the Wireshark plugins directory

For Linux:
```bash
cp ./csp.lua ~/.local/lib/wireshark/plugins/csp.lua
cp ./rdp.lua ~/.local/lib/wireshark/plugins/rdp.lua
cp ./efp.lua ~/.local/lib/wireshark/plugins/efp.lua
```

Now open Wireshark, and the plugins should be loaded.
If CSP packets are not dissected at all, make sure the plugins are loaded.
They should appear under Help->About Wireshark->Plugins

If you like colors, here are some recommended color filters:
| Name | Filter | Foreground | Background |
| ---- | ------ | ---------- | ---------- |
| CSP CRC32 Errors | csp.crc.status=="Bad" | #f78787 | #12272e |  
|CSP.RDP|csp.rdp| #12272e | #e7e6ff | 
|CSP|csp| #12272e| #daeeff |


You can add the filters manually in View->Coloring Rules...
Or you can add this to your colorfilters file
```
@Checksum Errors@csp.crc.status=="Bad"@[4626,10023,11822][63479,34695,34695]
@CSP.RDP@csp.rdp@[59367,59110,65535][4626,10023,11822]
@CSP@csp@[56026,61166,65535][4626,10023,11822]
```
which is located in `~/.config/wireshark/colorfilters` on linux.

> [!NOTE] 
> Make Sure the color filters are above (higher priority) the default Broadcast filter.


## Development

Add [wireshark_lua_api.lua](https://github.com/JCalHij/wireshark_lua_api) to the repository root to avoid lsp errors and most warnings

I recommend using [lua_ls](https://github.com/LuaLS/lua-language-server).
If you're using a different language server, you can make an equivalent config from [.luarc.json](./.luarc.json)






