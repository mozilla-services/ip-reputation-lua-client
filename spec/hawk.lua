describe(
   "ip-reputation hawk module", function()
      it("should exist", function()
            assert.truthy(require("ip-reputation").hawk)
      end)

      it("should correctly calculate a sha256 hawk auth header", function()
            local hawk = require("ip-reputation").hawk

            local creds = {
               id = '123456',
               key = '2983d45yun89q',
               algorithm = 'sha256',
            }

            local req = {
               method = 'POST',
               host = 'example.net',
               port = '443',
               resource = '/somewhere/over/the/rainbow',
               ts = 1353809207,
               nonce = 'Ygvqdz',
               -- app = nil,
               -- dlg = nil,
            }

            local options = {
               ext = 'Bazinga!',
               payload = 'something to write about',
               content_type = 'text/plain',
            }
            assert.Equal('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", ext="Bazinga!", mac="q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8="', hawk.header(creds, req, options))
      end)

      it("should fail to calculate a none hashed hawk auth header", function()
            local hawk = require("ip-reputation").hawk
            local creds = {
               id = '123456',
               key = '2983d45yun89q',
               algorithm = 'none',
            }

            local req = {
               method = 'POST',
               host = 'example.net',
               port = '443',
               resource = '/somewhere/over/the/rainbow',
               ts = 1353809207,
               nonce = 'Ygvqdz',
               -- app = nil,
               -- dlg = nil,
            }

            local options = {
               ext = 'Bazinga!',
               payload = 'something to write about',
               content_type = 'text/plain',
            }
            assert.has_error(function ()
                  hawk.header(creds, req, options)
                             end, 'Unsupported algorithm.')
      end)


end)
