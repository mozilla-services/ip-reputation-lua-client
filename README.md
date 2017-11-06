# ip-reputation-lua-client
Lua client library for the [IP Reputation Service / tigerblood](https://github.com/mozilla-services/tigerblood)

## Usage

```lua
local rep = require("ip-reputation")

rep.configure({
  base_url = "http://localhost:8080",
  id = "root",
  key = "toor",
})

rep.add('127.0.0.1', 50)
rep.get('127.0.0.1')
rep.update('127.0.0.1', 5)
rep.send_violation('127.0.0.1', 'test_violation')
rep.send_violations({
  {ip='127.0.0.1', violation='test_violation', weight = 10},
  {ip='127.0.0.2', violation='test_violation', weight = 20},
})
rep.remove('127.0.0.1')
```

## TODO

- [ ] hindsight / lua sandbox support
- [ ] openresty support

## Done

- [x] lua impl
- [x] hawk signing
- [x] publish [luarock](http://luarocks.org/modules/gguthemozillacom/ip-reputation)
