describe("ip-reputation client module", function()

  it("should exist", function()
    assert.truthy(require("ip-reputation"))
  end)

  it("should not get reputation for a nonexistent IP", function()
    local rep = require("ip-reputation")

    rep.configure({
      base_url = "http://localhost:8080",
      id = "root",
      key = "toor",
    })

    local resp = rep.get('127.0.0.1')

    assert.Equal(404, resp.status_code)
  end)

  it("should not update reputation for a nonexistent IP", function()
    local rep = require("ip-reputation")

    rep.configure({
      base_url = "http://localhost:8080",
      id = "root",
      key = "toor",
    })

    local resp = rep.update('127.0.0.1', 5)

    assert.Equal(404, resp.status_code)
  end)

  it("should remove reputation for a nonexistent IP", function()
    local rep = require("ip-reputation")

    rep.configure({
      base_url = "http://localhost:8080",
      id = "root",
      key = "toor",
    })

    local resp = rep.remove('127.0.0.1')

    assert.Equal(200, resp.status_code)
  end)

  -- the following tests need to run in order

  it("should add reputation for a new IP", function()
    local rep = require("ip-reputation")

    rep.configure({
      base_url = "http://localhost:8080",
      id = "root",
      key = "toor",
    })

    local resp = rep.add('127.0.0.1', 50)

    assert.Equal(201, resp.status_code)
  end)

  it("should not add reputation for a existing IP", function()
    local rep = require("ip-reputation")

    rep.configure({
      base_url = "http://localhost:8080",
      id = "root",
      key = "toor",
    })

    local resp = rep.add('127.0.0.1', 50)

    assert.Equal(409, resp.status_code)
    assert.Equal('Reputation is already set for that IP.', resp.body)
  end)

  it("should get reputation for a existing IP", function()
    local rep = require("ip-reputation")

    rep.configure({
      base_url = "http://localhost:8080",
      id = "root",
      key = "toor",
    })

    local resp = rep.get('127.0.0.1')

    assert.Equal(200, resp.status_code)
    assert.Equal('{"IP":"127.0.0.1","Reputation":50}', resp.body)
  end)

  it("should update reputation for a existing IP", function()
    local rep = require("ip-reputation")

    rep.configure({
      base_url = "http://localhost:8080",
      id = "root",
      key = "toor",
    })

    local resp = rep.update('127.0.0.1', 5)

    assert.Equal(200, resp.status_code)
    assert.Equal('', resp.body)
  end)

  it("should remove reputation for a existing IP", function()
    local rep = require("ip-reputation")

    rep.configure({
      base_url = "http://localhost:8080",
      id = "root",
      key = "toor",
    })

    local resp = rep.remove('127.0.0.1')
    assert.Equal(200, resp.status_code)

    local resp = rep.get('127.0.0.1')
    assert.Equal(404, resp.status_code)
  end)

  it("should send a violation", function()
    local rep = require("ip-reputation")

    rep.configure({
      base_url = "http://localhost:8080",
      id = "root",
      key = "toor",
    })

    local resp = rep.get('127.0.0.1')
    assert.Equal(404, resp.status_code)

    local resp = rep.send_violation('127.0.0.1', 'test_violation')
    assert.Equal(204, resp.status_code)

    local resp = rep.get('127.0.0.1')
    assert.Equal(200, resp.status_code)
    assert.Equal('{"IP":"127.0.0.1","Reputation":70}', resp.body)
  end)

  it("should clean up inserted reputation from send violation test", function()
    local rep = require("ip-reputation")

    rep.configure({
      base_url = "http://localhost:8080",
      id = "root",
      key = "toor",
    })

    local resp = rep.remove('127.0.0.1')
    assert.Equal(200, resp.status_code)
  end)

  -- TODO: GET timeout
  -- TODO: invalid SSL cert
end)
