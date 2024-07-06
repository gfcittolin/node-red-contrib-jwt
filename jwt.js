module.exports = function (RED) {
    var jwt = require('jsonwebtoken');
    var fs = require('fs');
    function JwtSign(n) {
        RED.nodes.createNode(this, n);
        this.name = n.name;
        this.payload = n.payload;
        this.alg = n.alg;
        this.exp = n.exp;
        this.jwkurl = n.jwkurl;
        this.jwkkid = n.jwkkid;
        this.secret = n.secret;
        this.key = n.key;
        this.signvar = n.signvar;
        this.storetoken = n.storetoken;
        var node = this;

        if (node.jwkurl) {
            attachJWK(node.jwkurl, node);
        }else{
            node.jwk = false;
            // changed to load key on deploy level and not on runtime level why fs.readFileSync is sync.
            if (node.alg === 'RS256' ||
                node.alg === 'RS384' ||
                node.alg === 'RS512' || 
                node.alg === 'ES256' ||
                node.alg === 'ES384' ||
                node.alg === 'ES512') {
                node.secret = process.env.NODE_RED_NODE_JWT_PRIVATE_KEY || fs.readFileSync(node.key);
            } else {
                node.secret = process.env.NODE_RED_NODE_JWT_SECRET || node.secret;
            }
        }
        node.on('input', function (msg, send, done) {
            send = send || function() { node.send.apply(node,arguments) }
            done = done || function(err) { if(err)node.error(err, msg); }

            const unsignedToken = msg[node.signvar];

            function handleSignResult(err, token) {
                if (err) {
                    done(err);
                } else {
                    msg[node.storetoken] = token;
                    send(msg);
                    done();
                }
            }

            try {
                if (node.jwk) {
                    //use JWK to sign
                    const kid = node.jwkkid;
                    node.findJWKKeyById(kid, key => {
                        const secret = key && key.key.toPrivateKeyPEM();

                        const jwtSignOpts = { algorithm: node.alg, expiresIn: node.exp, keyid: kid }
                        jwt.sign(unsignedToken, secret, jwtSignOpts, handleSignResult);
                    });
                } else {
                    const jwtSignOpts = { algorithm: node.alg, expiresIn: node.exp }
                    jwt.sign(unsignedToken, node.secret, jwtSignOpts, handleSignResult);
                }
            } catch (err) {
                node.error(err.message);
            }
        });
    }
    RED.nodes.registerType("jwt sign", JwtSign);

    function contains(a, obj) {
        for (var i = 0; i < a.length; i++) {
            if (a[i] === obj) {
                return true;
            }
        }
        return false;
    }

    function JwtVerify(n) {
        RED.nodes.createNode(this, n);
        this.name = n.name;
        this.payload = n.payload;
        this.alg = n.alg;
        this.jwkurl = n.jwkurl;
        this.secret = n.secret;
        this.key = n.key;
        this.signvar = n.signvar;
        this.storetoken = n.storetoken;
        var node = this;

        if (node.jwkurl) {
            attachJWK(node.jwkurl, node);
        }else{
            node.jwk = false;
            if (contains(node.alg, 'RS256') || contains(node.alg, 'RS384') || contains(node.alg, 'RS512') || contains(node.alg, 'ES512') || contains(node.alg, 'ES384') || contains(node.alg, 'ES256')) {
                node.secret = process.env.NODE_RED_NODE_JWT_PUBLIC_KEY || fs.readFileSync(node.key);
            } else {
                node.secret = process.env.NODE_RED_NODE_JWT_SECRET || node.secret;
            }
        }

        node.on('input', function (msg, send, done) {
            send = send || function() { node.send.apply(node,arguments) }
            done = done || function(err) { if(err)node.error(err, msg); }
            if (node.signvar === 'bearer') {
                if (msg.req !== undefined && msg.req.get('authorization') !== undefined) {
                    var authz = msg.req.get('authorization').split(' ');
                    if(authz.length == 2 && (authz[0] === 'Bearer' || (msg.prefix !== undefined && authz[0] === msg.prefix))){
                        msg.bearer = authz[1];
                   }
                } else if (msg.req.query.access_token !== undefined) {
                    msg.bearer = msg.req.query.access_token;
                } else if (msg.req.body !== undefined && msg.req.body.access_token !== undefined) {
                    msg.bearer = msg.req.body.access_token;
                }
            }

            const signedToken = msg[node.signvar];

            function handleVerificationResult(err, decoded) {
                if (err) {
                    msg['payload'] = err;
                    msg['statusCode'] = 401;
                    done(err);
                } else {
                    msg[node.storetoken] = decoded;
                    send([msg, null]);
                    done();
                }
            }

            if (node.jwk) {
                //use JWK to verify
                var header = GetTokenHeader(signedToken);
                //find kid if present
                var kid = header.kid;

                node.findJWKKeyById(kid, key => {
                    const secret = key && key.key.toPublicKeyPEM();

                    jwt.verify(signedToken, secret, { algorithms: node.alg }, handleVerificationResult);
                })
            } else {
                jwt.verify(signedToken, node.secret, { algorithms: node.alg }, handleVerificationResult);
            }
        });
    }
    RED.nodes.registerType("jwt verify", JwtVerify);

    function attachJWK(url, node) {
        const njwk = require('node-jwk');
        const request = require("request");
        let jwkSet;

        node.jwk = true;
        node.findJWKKeyById = function(kid, cb) {
            // return first key on set if kid not provided
            if (!kid) return process.nextTick(() => cb(jwkSet && jwkSet.keys[0]));

            const cachedKey = jwkSet && jwkSet.findKeyById(kid);
            if (cachedKey) {
                // cached key found, return it
                process.nextTick(() => cb(cachedKey));

            } else {   
                //cached key not found, try refreshing the cache
                refreshCache(() => {
                    //get from fetched ...otherwise use first key in set
                    const key = jwkSet && jwkSet.findKeyById(kid);
                    cb(key);
                });
            }
        }

        function refreshCache(cb) {
            request({
                url: url,
                json: true
            }, function (error, response, body) {
                if (!error && response.statusCode === 200) {
                    jwkSet = njwk.JWKSet.fromObject(body);
                    console.log(jwkSet._keys.length + " keys loaded from JWK: " + url );
                } else {
                    console.log("Unable to fetch JWK: " + url);
                }
                if (cb) cb();
            })
        }

        //populate initial cache
        refreshCache();
    }

    function GetTokenHeader(token) {
        var json = jwt.decode(token, {complete: true});
        return json.header;
    }
};


