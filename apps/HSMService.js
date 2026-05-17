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
 * @fileoverview A simple HSM maintaince service
 */

const SmartCardHSM		= require('scsh/sc-hsm/SmartCardHSM').SmartCardHSM;
const ManagePKA			= require('scsh/sc-hsm/ManagePKA').ManagePKA;
const HSMUI			= require('scsh/srv-cc1/HSMUI').HSMUI;
const HSMKeyStore					= require('scsh/sc-hsm/HSMKeyStore').HSMKeyStore;
const CVC = require("scsh/eac/CVC").CVC;
const PKIXCommon = require("scsh/x509/PKIXCommon").PKIXCommon;



/**
 * Class implementing the SmartCard-HSM management service
 *
 * @constructor
 */
function HSMService() {
	this.type = "SC-HSM";
	this.name = "Management";
	this.hsmlist = [];
	this.hsmmap = [];
	this.crypto = new Crypto();
	this.authenticationRequired = false;
	this.roleRequired = 0;
	Card.setCardEventListener(this);
}

exports.HSMService = HSMService;



/**
 * Create a new UI session
 *
 * @param {HttpSession} session the new session context
 */
HSMService.prototype.newUI = function(session) {
	var ui = new HSMUI(this, session);
	return ui;
}



/**
 * Add HSMState to managed list, possibly updating existing state object
 *
 * @param {HSMState} hsm the state object
 */
HSMService.prototype.addOrUpdateHSMState = function(state) {
	var oldstate = this.hsmmap[state.path];
	if (oldstate) {
		oldstate.path = state.path;
		oldstate.sc = state.sc;
		oldstate.deviceId = state.deviceId;
		oldstate.error = state.error;
		return oldstate;
	} else {
		this.hsmmap[state.path] = state;
		this.hsmlist.push(state);
		return state;
	}
}



/**
 * Return a list of registered HSMs
 * @type String[]
 * @return the list of HSM path identifier
 */
HSMService.prototype.getHSMList = function() {
	var list = [];
	for (var i = 0; i < this.hsmlist.length; i++) {
		list.push(this.hsmlist[i].path);
	}
	return list;
}



/**
 * Enumerate key domains on a SmartCard-HSM.
 *
 * @param {SmartCardHSM} sc the hsm.
 * @type Array
 * @return an array of key domain status objects.
 */
HSMService.prototype.enumerateKeyDomains = function(sc) {
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
 * Enumerate keys
 *
 * @param {SmartCardHSM} sc the hsm.
 * @type Array
 * @return an array of key objects.
 */
HSMService.prototype.enumerateKeys = function(sc) {
	var ks = new HSMKeyStore(sc);

	var keyIds = sc.getKeyIds();
	var keys = [];

	for (var j = 0; j < keyIds.length; j++) {
		var key = sc.getKey(keyIds[j]);

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

		if (ks.hasCertificate(key)) {
			var cert = ks.getCertificate(key);
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
					pubkey.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256r1", OID));
				}
				spki = PKIXCommon.createECSubjectPublicKeyInfo(pubkey, false);
			}

			desc.cert = cert.toString(BASE64);
			desc.pubkey = spki.getBytes().toString(BASE64);
		}
		keys.push(desc);
	}
	return keys;
}



/**
 * Obtain card service for device
 *
 * @param {HSMState} hsm the state object
 * @param {Card} the card object representing the link to the device
 */
HSMService.prototype.getCardService = function(state, card) {
	try	{
		var sc = new SmartCardHSM(card);
	}
	catch(e if e instanceof GPError) {
		throw new GPError(module.id, GPError.DEVICE_FAILED, 0, "This does not seem to be a SmartCard-HSM");
	}

	// Determine device unique path
	var devAutCert = sc.readBinary(SmartCardHSM.C_DevAut);
	var chain = SmartCardHSM.validateCertificateChain(this.crypto, devAutCert);
	if (chain == null) {
		throw new GPError(module.id, GPError.CRYPTO_FAILED, 0, "Could not validate device certificate. Is this a genuine SmartCard-HSM ?");
	}
	if (state.path) {
		if (chain.path != state.path) {
			throw new GPError(module.id, GPError.DEVICE_ERROR, 0, "Device is " + chain.path + " but should be " + state.path +
			". Please insert correct SmartCard-HSM or connect to a different SmartCard-HSM" );
		}
	} else {
		state.path = chain.path;
	}

	state.deviceId = chain.devicecert.getCHR().getBytes();
	state.defaultKeyDomain = chain.publicKey.getComponent(Key.ECC_QX).toString(HEX);

	sc.openSecureChannel(this.crypto, chain.publicKey);

	state.error = undefined;
	state.sc = sc;
	state.readerName = card.readerName;
	state.update();
}



/**
 * Handle inbound request from remote terminal
 *
 * @param {HttpSession} session the session object
 * @param {String} pathInfo the pathinfo part of the URL
 */
HSMService.prototype.handleCard = function(session, pathInfo) {
	GPSystem.trace("Handle card for session " + session.id);
	var card = new Card(session.cardTerminal);

	try	{
		var state = new HSMState();
		this.getCardService(state, card);
		state = this.addOrUpdateHSMState(state);
		delete state.cp;
		state.isLocal = false;

		state.update();
	}
	catch(e if e instanceof GPError) {
		GPSystem.log(GPSystem.ERROR, module.id, e);
		card.nativeCardTerminal.sendNotification(-1, "Failure talking to card. Is this a SmartCard-HSM ?");
		GPSystem.trace(e);
	}
}



/**
 * Return the full list of maintained states
 *
 * @type HSMState[]
 * @return the list of maintained HSM states
 */
HSMService.prototype.getHSMStates = function() {
	return this.hsmlist;
}



/**
 * Return the list of maintained states for active HSMs
 *
 * @type HSMState[]
 * @return the list of active HSM states
 */
HSMService.prototype.getActiveHSMStates = function() {
	var states = [];
	for (var i = 0; i < this.hsmlist.length; i++) {
		var state = this.hsmlist[i];
		state.update();
		if (!state.isOffline() && state.isUserAuthenticated()) {
			if (typeof(state.keyDomains) == "undefined") {
				state.keyDomains = this.enumerateKeyDomains(state.sc);
				state.keys = this.enumerateKeys(state.sc);
			}
			states.push(state);
		}
	}
	return states;
}



/**
 * Return true if SmartCard-HSM with given path is registered
 *
 * @type boolean
 * @return true if this HSM is known
 */
HSMService.prototype.hasHSM = function(path) {
	return (typeof(this.hsmmap[path]) != "undefined");
}



/**
 * Return updated HSM state for given device
 *
 * @param {String} path the device id
 * @type HSMState
 * @return the state object
 */
HSMService.prototype.getHSMState = function(path) {
	var state = this.hsmmap[path];
	if (state) {
		state.update();
	}
	return state;
}



/**
 * Perform User PIN verification
 *
 * @param {HSMState} hsm the state object
 * @param {String} pin the optional provided PIN
 * @type String
 * @return Result string
 */
HSMService.prototype.verifyUserPIN = function(hsm, pin) {
	if (!hsm.sc) {
		return "HSM is offline";
	}

	try	{
		if (pin) {
			hsm.pinsw = hsm.sc.verifyUserPIN(new ByteString(pin, ASCII));
		} else {
			hsm.pinsw = hsm.sc.verifyUserPIN();
		}
	}
	catch(e if e instanceof GPError) {
		GPSystem.log(GPSystem.ERROR, module.id, "PIN verification failed with " + e.message);
		hsm.pinsw = hsm.sc.queryUserPINStatus();
	}

	return SmartCardHSM.describePINStatus(hsm.pinsw, "User PIN");
}



HSMService.prototype.cardInserted = function(reader) {
	print("### Inserted " + reader)
}



HSMService.prototype.cardRemoved = function(reader) {
	for (var i = 0; i < this.hsmlist.length; i++) {
		var state = this.hsmlist[i];
		if (reader == state.readerName) {
			print("### " + state.path + " is no offline");
			delete state.sc;
		}
	}
}



HSMService.prototype.toString = function() {
	return "HSMService for SmartCard-HSM";
}



/**
 * Maintain the SmartCard-HSM state information
 *
 * @param {String} path the SmartCard-HSM unique identifier
 * @constructor
 */
function HSMState(path) {
	this.path = path;
	this.isLocal = false;
}



/**
 * Returns true if SmartCard-HSM is no longer connected
 *
 * @type boolean
 * @return true if disconnected
 */
HSMState.prototype.isOffline = function() {
	return !this.sc;
}



/**
 * Returns true if protected PIN verification is supported
 *
 * @type boolean
 * @return true if protected PIN supported
 */
HSMState.prototype.hasProtectedPINEntry = function() {
	return this.protectedPINEntry;
}



/**
 * Returns true if user is authenticated
 *
 * @type boolean
 * @return true if user is authenticated
 */
HSMState.prototype.isUserAuthenticated = function() {
	return this.pinsw == 0x9000;
}



/**
 * Update status
 */
HSMState.prototype.update = function() {
	if (this.isOffline()) {
		return;
	}

	try	{
		this.pinsw = this.sc.queryUserPINStatus();

		this.pka = new ManagePKA(this.sc, this.deviceId);

		if (!this.pka.isActive()) {
			this.pka = null;
		}
	}
	catch(e if e instanceof GPError) {
		GPSystem.log(GPSystem.INFO, module.id, "Device " + this.path + " failed with " + e.message);
		this.error = e.message;
		this.sc = undefined;		// Device is offline, e.g. removed
	}
}



/**
 * Logout from SmartCard-HSM
 */
HSMState.prototype.logout = function() {
	if (!this.sc) {
		return;
	}

	this.sc.logout();
	this.update();
}



/**
 * Disconnect remote connection
 */
HSMState.prototype.disconnect = function(stayloggedin) {
	if (!this.sc) {
		return;
	}

	if (stayloggedin) {
		this.sc.card.sendSecMsgApdu(Card.ALL, 0x00, 0x20, 0x01, 0x81);
	}
	this.sc.card.close();
	this.sc = null;
	this.pka = null;
}



HSMState.prototype.toString = function() {
	return (this.isLocal ? "Local: " : "Remote: ") + this.path;
}
