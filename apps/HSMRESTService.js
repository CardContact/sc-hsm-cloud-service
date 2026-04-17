/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|
 * |#       #|  Copyright (c) 1999-2010 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  ---------
 *
 *  This file is part of OpenSCDP.
 *
 *  OpenSCDP is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  OpenSCDP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCDP; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @fileoverview A simple REST-API to access a Cloud-HSM
 */

const SmartCardHSM = require('scsh/sc-hsm/SmartCardHSM').SmartCardHSM;
const CVC = require("scsh/eac/CVC").CVC;
const PKIXCommon = require("scsh/x509/PKIXCommon").PKIXCommon;
const Router = require("scsh/srv-cc1/Router").Router;


/**
 * Class implementing the SmartCard-HSM REST service
 *
 * @constructor
 */
function HSMRESTService(hsmService) {
	this.hsmService = hsmService;

	this.model = [];

	this.router = new Router();
	this.router.add("hsms",            "/api/hsms", this);
	this.router.add("hsm",             "/api/hsms/:hsmid", this);
	this.router.add("hsmkeys",         "/api/hsms/:hsmid/keys", this);
	this.router.add("hsmkey",          "/api/hsms/:hsmid/keys/:keyid", this);
	this.router.add("hsmkeyop",        "/api/hsms/:hsmid/keys/:keyid/:op", this);

	this.router.add("keys",            "/api/keys", this);
	this.router.add("key",             "/api/keys/:keyid", this);
	this.router.add("keyop",           "/api/keys/:keyid/:op", this);

	this.router.add("keydomains",      "/api/keydomains", this);
	this.router.add("keydomain",       "/api/keydomains/:keydomainid", this);
	this.router.add("keydomainkeys",   "/api/keydomains/:keydomainid/keys", this);
	this.router.add("keydomainkey",    "/api/keydomains/:keydomainid/keys/:keyid", this);
	this.router.add("keydomainkeyop",  "/api/keydomains/:keydomainid/keys/:keyid/:op", this);

	this.router.dump();
}

exports.HSMRESTService = HSMRESTService;



/**
 * Transform the path identifier into dot-separted format.
 *
 * @param {String} path the path with slashes
 * @type String
 * @return the path in dotted format.
 */
HSMRESTService.transformTokenId = function(path) {
	return path.substring(1).replaceAll("/",".");
}



/**
 * Enumerate key domains on a SmartCard-HSM.
 *
 * @param {SmartCardHSM} sc the hsm.
 * @type Array
 * @return an array of key domain status objects-
 */
HSMRESTService.prototype.enumerateKeyDomains = function(sc) {
	var kdid = 0;
	var keyDomains = [];

	do	{
		var status = sc.queryKeyDomainStatus(kdid);
		if ((status.sw == 0x6D00) || (status.sw == 0x6A86)) {
			return keyDomains;
		}

		if (status.sw == 0x9000) {
			var id = undefined;

			if (status.keyDomain) {
				id = status.keyDomain.toString(HEX);
			} else if (status.outstanding == 0) {
				id = status.kcv.toString(HEX);
			}

			status.label = sc.getKeyDomainLabel(kdid);

			if (id) {
				var dom = { id: id, status: status };
				if (status.label) {
					dom.label = status.label;
				}
				keyDomains[kdid] = dom;
			}
		}

		kdid++;
	} while ((status.sw == 0x9000) || (status.sw == 0x6A88));

	return keyDomains;
}



/**
 * Copy elements from a JSON object, excluding properties in the exception list
 *
 * @param {Object} source the source JSON object.
 * @param {String[]} the list of properties to be excluded in the copy.
 * @type Object
 * @return the copy
 */
HSMRESTService.cloneExcept = function(source, exeptionList) {
	var dest = {};

	for (var i in source) {
		if (exeptionList.indexOf(i) == -1) {
			dest[i] = source[i];
		}
	}

	return dest;
}



/**
 * Update the internal data model, if something has changed.
 */
HSMRESTService.prototype.updateModel = function() {
	var states = this.hsmService.getHSMStates();
	if (states.length == this.model.length) {
		return;
	}

	var model = [];
	for (var i = 0; i < states.length; i++) {
		var state = states[i];

		var cp = this.hsmService.getCryptoProvider(state.path, false);

		var keyDomains = this.enumerateKeyDomains(cp.sc);

		var keyIds = cp.sc.getKeyIds();
		var keys = [];

		for (var j = 0; j < keyIds.length; j++) {
			var key = cp.sc.getKey(keyIds[j]);

			var desc = {
				id: key.getPKCS15Id().toString(HEX),
				label: key.getLabel(),
				type: key.getType(),
				size: key.getSize(),
				key: key
			};

			if (typeof(key.useCounter) != "undefined") {
				desc.keyUseCounter = key.useCounter;
			}
			if (typeof(key.algorithms) != "undefined") {
				desc.algorithms = SmartCardHSM.decodeAlgorithmList(key.algorithms);
			}

			if (typeof(key.keyDomain) != "undefined") {
				desc.keyDomainIdx = key.keyDomain;
			}

			if (cp.ks.hasCertificate(key)) {
				var cert = cp.ks.getCertificate(key);
				var pubkey;
				if (cert.byteAt(0) == 0x30) {
					var xcert = new X509(cert);
					pubkey = xcert.getPublicKey();
				} else {
					var cvc = new CVC(cert);
					pubkey = cvc.getPublicKey();
				}

				var spki;
				if (pubkey.getComponent(Key.MODULUS)) {
					spki = PKIXCommon.createRSASubjectPublicKeyInfo(pubkey);
				} else {
					if (pubkey.getComponent(Key.ECC_CURVE_OID) == undefined) {
						pubkey.getComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256r1", OID));
					}
					spki = PKIXCommon.createECSubjectPublicKeyInfo(pubkey, false);
				}

				desc.cert = cert.toString(BASE64);
				desc.pubkey = spki.getBytes().toString(BASE64);
			}
			keys.push(desc);
		}

		var id = HSMRESTService.transformTokenId(state.path);

		model.push( {
			id: id,
			keyDomains: keyDomains,
			defaultKeyDomain: state.defaultKeyDomain,
			keys: keys
		});
	}

	this.model = model;
}



/**
 * Locate the key in the data model that matches the filter criteria.
 *
 * @param {Object} filter the filter criteria.
 * @type SmartCardHSMKey
 * @return the found key or undefined.
 */
HSMRESTService.prototype.locateKey = function(filter) {
	this.updateModel();

	for (var i = 0; i < this.model.length; i++) {
		var hsm = this.model[i];
		if (filter.hsmid && (hsm.id != filter.hsmid)) {
			continue;
		}

		for (var j = 0; j < hsm.keys.length; j++) {
			var key = hsm.keys[j];
			if (filter.keyid == key.id) {
				return key.key;
			}
		}
	}
}



/**
 * Sign the provided hash
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {SmartCardHSMKey] key the key
 */
HSMRESTService.prototype.signHash = function(req, res, key) {
	try	{
		var str = req.getEntityAsString();
		var r = JSON.parse(str);
		GPSystem.log(GPSystem.INFO, module.id, "signhash Request " + JSON.stringify(r, null, "\t"));

		if (typeof(r.algo) == "undefined") {
			throw new GPError(module.id, GPError.INVALID_DATA, 0, "Request must contain 'algo' field");
		}

		var mech;
		switch(r.algo) {
			case "ECDSA":
				mech = Crypto.ECDSA;
				break;
			case "RSA_PKCS1":
				mech = Crypto.RSA_PKCS1;
				break;
			case "RSA_PSS":
				mech = Crypto.RSA_PSS;
				break;
			default:
				throw new GPError(module.id, GPError.INVALID_DATA, 0, "Unknown algorithm " + r.algo);
		}

		if (typeof(r.hash) == "undefined") {
			throw new GPError(module.id, GPError.INVALID_DATA, 0, "Request must contain 'hash' field");
		}

		var hash = new ByteString(r.hash, HEX);
	} catch(e) {
		GPSystem.log(GPSystem.ERROR, module.id, e);
		res.setStatus(HttpResponse.SC_BAD_REQUEST);
		return;
	}

	var signature = key.sign(mech, hash);

	var r = {
		signature: signature.toString(HEX)
	};

	var str = JSON.stringify(r, null, "\t");
	res.setContentType("application/json");
	res.setStatus(HttpResponse.SC_OK);
	res.println(str);
}



/**
 * Handle operations in the key object
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
HSMRESTService.prototype.handleKeyOps = function(req, res) {
	if (req.method != "POST") {
		res.setStatus(HttpResponse.SC_METHOD_NOT_ALLOWED);
		return;
	}

	var key = this.locateKey(req.router.params);

	if (key == undefined) {
		res.setStatus(HttpResponse.SC_NOT_FOUND);
		return;
	}

	switch(req.router.params.op) {
		case "signhash":
			this.signHash(req, res, key);
			break;
		default:
			res.setStatus(HttpResponse.SC_NOT_FOUND);
	}
}



/**
 * Create the HSM list
 *
 * @param {Object} filter filter criteria
 */
HSMRESTService.prototype.getHSMList = function(filter) {
	this.updateModel();

	var hsmList = [];

	for (var i = 0; i < this.model.length; i++) {
		var hsm = this.model[i];
		if (filter.hsmid && (hsm.id != filter.hsmid)) {
			continue;
		}

		// Clone key domains
		var keyDomains = [];
		for (var j = 0; j < hsm.keyDomains.length; j++) {
			if (hsm.keyDomains[j]) {
				keyDomains.push(HSMRESTService.cloneExcept(hsm.keyDomains[j], [ "status" ]));
			}
		}

		// Clone keys, resolving the keyDomain link
		var keys = [];
		for (var j = 0; j < hsm.keys.length; j++) {
			var key = hsm.keys[j];
			if (filter.keyid && (key.id != filter.keyid)) {
				continue;
			}

			var desc = HSMRESTService.cloneExcept(key, [ "keyDomainIdx", "key" ]);

			if (typeof(key.keyDomainIdx) != "undefined") {
				desc.keyDomain = hsm.keyDomains[key.keyDomainIdx].id;
			} else {
				desc.keyDomain = hsm.defaultKeyDomain;
			}
			keys.push(desc);
		}

		hsmList.push( {
			id: hsm.id,
			defaultKeyDomain: hsm.defaultKeyDomain,
			keyDomains: keyDomains,
			keys: keys
		});
	}

	return hsmList;
}



/**
 * Handle HTTP requests for the hsms resource
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
HSMRESTService.prototype.handleHSM = function(req, res) {
	var hsmList = this.getHSMList(req.router.params);

	var r = hsmList;

	var id = req.router.params.hsmid;
	if (req.router.params.hsmid) {
		if (hsmList.length < 1) {
			res.setStatus(HttpResponse.SC_NOT_FOUND);
			return;
		}

		r = hsmList[0];
	}

	if (req.method != "GET") {
		res.setStatus(HttpResponse.SC_METHOD_NOT_ALLOWED);
		return;
	}

	var str = JSON.stringify(r, null, "\t");
	res.setContentType("application/json");
	res.setStatus(HttpResponse.SC_OK);
	res.println(str);
}



/**
 * Handle HTTP requests for the hsms/:hsmid/keys keys resource
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
HSMRESTService.prototype.handleKeysOnHSM = function(req, res) {
	var hsmList = this.getHSMList(req.router.params);

	if (hsmList.length < 1) {
		res.setStatus(HttpResponse.SC_NOT_FOUND);
		return;
	}

	var keys = hsmList[0].keys;
	var r = keys;

	if (req.router.params.keyid) {
		if (keys.length < 1) {
			res.setStatus(HttpResponse.SC_NOT_FOUND);
			return;
		}
		r = keys[0];
	}

	if (req.method != "GET") {
		res.setStatus(HttpResponse.SC_METHOD_NOT_ALLOWED);
		return;
	}

	var str = JSON.stringify(r, null, "\t");
	res.setContentType("application/json");
	res.setStatus(HttpResponse.SC_OK);
	res.println(str);
}



/**
 * Create the key list
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url the components of the URL
 */
HSMRESTService.prototype.getKeyList = function(filter) {
	this.updateModel();

	var keyList = [];
	var keyMap = {};

	for (var i = 0; i < this.model.length; i++) {
		var hsm = this.model[i];

		// Clone keys, resolving the keyDomain link
		for (var j = 0; j < hsm.keys.length; j++) {
			var key = hsm.keys[j];

			if (filter.keyid && (key.id != filter.keyid)) {
				continue;
			}

			var desc = keyMap[key.id];
			if (typeof(desc) == "undefined") {
				var desc = HSMRESTService.cloneExcept(key, [ "keyDomainIdx", "key" ]);
				if (typeof(key.keyDomainIdx) != "undefined") {
					desc.keyDomain = hsm.keyDomains[key.keyDomainIdx].id;
				} else {
					desc.keyDomain = hsm.defaultKeyDomain;
				}
				desc.hsms = [];
				keyList.push(desc);
				keyMap[key.id] = desc;
			}
			desc.hsms.push(hsm.id);
		}
	}

	return keyList;
}



/**
 * Handle HTTP requests for the key resource
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url the components of the URL
 */
HSMRESTService.prototype.handleKey = function(req, res, url) {
	var keyList = this.getKeyList(req.router.params);

	var r = keyList;

	if (req.router.params.keyid) {
		if (keyList.length < 1) {
			res.setStatus(HttpResponse.SC_NOT_FOUND);
			return;
		}

		r = keyList[0];
	}

	if (req.method != "GET") {
		res.setStatus(HttpResponse.SC_METHOD_NOT_ALLOWED);
		return;
	}

	var str = JSON.stringify(r, null, "\t");
	res.setContentType("application/json");
	res.setStatus(HttpResponse.SC_OK);
	res.println(str);
}



/**
 * Create the key domain list
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url the components of the URL
 */
HSMRESTService.prototype.getKeyDomainList = function(filter) {
	this.updateModel();

	var keyDomainList = [];
	var keyDomainMap = {};
	var keyMap = {};

	for (var i = 0; i < this.model.length; i++) {
		var hsm = this.model[i];

		var desc = { id: hsm.defaultKeyDomain, hsms: [ hsm.id ], keys: [] };
		keyDomainList.push(desc);
		keyDomainMap[desc.id] = desc;

		for (var j = 0; j < hsm.keyDomains.length; j++) {
			var keydomain = hsm.keyDomains[j];

			desc = keyDomainMap[keydomain.id];
			if (typeof(desc) == "undefined") {
				var desc = HSMRESTService.cloneExcept(keydomain, [ "status" ]);
				desc.hsms = [];
				desc.keys = [];
				keyDomainList.push(desc);
				keyDomainMap[keydomain.id] = desc;
			}

			desc.hsms.push(hsm.id);
		}

		// Clone keys, resolving the keyDomain link
		for (var j = 0; j < hsm.keys.length; j++) {
			var key = hsm.keys[j];
			var desc = keyMap[key.id.toString(HEX)];
			if (typeof(desc) == "undefined") {
				var desc = HSMRESTService.cloneExcept(hsm.keys[j], [ "keyDomainIdx", "key" ]);
				if (typeof(hsm.keys[j].keyDomainIdx) != "undefined") {
					var id = hsm.keyDomains[hsm.keys[j].keyDomainIdx].id;
				} else {
					var id = hsm.defaultKeyDomain;
				}
				desc.hsms = [];
				keyDomainMap[id].keys.push(desc);
				keyMap[key.id] = desc;
			}
			desc.hsms.push(hsm.id.toString(HEX));
		}
	}

	return keyDomainList;
}



/**
 * Handle HTTP requests for the key domain resource
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url the components of the URL
 */
HSMRESTService.prototype.handleKeyDomain = function(req, res, url) {
	var keyDomainList = this.getKeyDomainList(req.router.params);

	var r = keyDomainList;

	if (req.router.params.keydomainid) {
		if (keyDomainList.length < 1) {
			res.setStatus(HttpResponse.SC_NOT_FOUND);
			return;
		}

		r = keyDomainList[0];
	}

	if (req.method != "GET") {
		res.setStatus(HttpResponse.SC_METHOD_NOT_ALLOWED);
		return;
	}

	var str = JSON.stringify(r, null, "\t");
	res.setContentType("application/json");
	res.setStatus(HttpResponse.SC_OK);
	res.println(str);
}



/**
 * Handle HTTP requests for the key domain resource
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url the components of the URL
 */
HSMRESTService.prototype.handleKeysOnKeyDomain = function(req, res, url) {
	var keyDomainList = this.getKeyDomainList(req.router.params);

	if (keyDomainList.length < 1) {
			res.setStatus(HttpResponse.SC_NOT_FOUND);
			return;
	}

	var keys = keyDomainList[0].keys;
	var r = keys;

	if (req.router.params.keyid) {
		if (keys.length < 1) {
			res.setStatus(HttpResponse.SC_NOT_FOUND);
			return;
		}
		r = keys[0];
	}

	if (req.method != "GET") {
		res.setStatus(HttpResponse.SC_METHOD_NOT_ALLOWED);
		return;
	}

	var str = JSON.stringify(r, null, "\t");
	res.setContentType("application/json");
	res.setStatus(HttpResponse.SC_OK);
	res.println(str);
}



/**
 * Handle HTTP requests
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
HSMRESTService.prototype.handleRoutedRequest = function(req, res) {

	switch(req.router.name) {
		case "hsms":
		case "hsm":
			this.handleHSM(req, res);
			break;
		case "hsmkeys":
		case "hsmkey":
			this.handleKeysOnHSM(req, res);
			break;
		case "hsmkeyop":
		case "keyop":
		case "keydomainkeyop":
			this.handleKeyOps(req, res);
			break;
		case "keys":
		case "key":
			this.handleKey(req, res);
			break;
		case "keydomain":
		case "keydomains":
			this.handleKeyDomain(req, res);
			break;
		case "keydomainkeys":
		case "keydomainkey":
			this.handleKeysOnKeyDomain(req, res);
			break;
		default:
			res.setStatus(HttpResponse.SC_NOT_FOUND);
			return;
	}
}



/**
 * Handle HTTP requests
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
HSMRESTService.prototype.handleRequest = function(req, res) {
	this.router.route(req, res);
}
