//
//  ---------
// |.##> <##.|  CardContact Software & System Consulting
// |#       #|  32429 Minden, Germany (www.cardcontact.de)
// |#       #|  Copyright (c) 1999-2006. All rights reserved
// |'##> <##'|  See file COPYING for details on licensing
//  ---------
//
// Setup runtime environment
//



//
// Determine platform id
//
function getPlatformID() {
	var sysid = GPSystem.getSystemID();
	sysid = sysid.toString(OID).split(".");
	sysid = parseInt(sysid[sysid.length - 5]);
	return sysid;
}



//
// Minimal assert() function
//
function assert(condition, message) {
	if (!condition) {
		if (!message) {
			message = "Assertion failed";
		} else {
			message = "Assertion failed - " + message;
		}
		throw new GPError("shell", GPError.USER_DEFINED, 0, message);
	}
}



// All GP classes report errors through GPError
defineClass("de.cardcontact.scdp.engine.Shell");
defineClass("de.cardcontact.scdp.gp.GPError");
defineClass("de.cardcontact.scdp.gp.GPSystem");
defineClass("de.cardcontact.scdp.gp.ByteString");
defineClass("de.cardcontact.scdp.gp.GPByteBuffer");
defineClass("de.cardcontact.scdp.gp.GPAtr");
defineClass("de.cardcontact.scdp.gp.Card");
defineClass("de.cardcontact.scdp.gp.GPKey");
defineClass("de.cardcontact.scdp.gp.GPCrypto");
defineClass("de.cardcontact.scdp.gp.GPXML");
defineClass("de.cardcontact.scdp.gp.GPTLV");
defineClass("de.cardcontact.scdp.gp.GPTLVList");
defineClass("de.cardcontact.scdp.gp.Application");
defineClass("de.cardcontact.scdp.gp.GPApplication");
defineClass("de.cardcontact.scdp.gp.GPSecurityDomain");
defineClass("de.cardcontact.scdp.gp.GPSecureChannel");
defineClass("de.cardcontact.scdp.gp.GPScp02");
defineClass("de.cardcontact.scdp.gp.GPScp03");
defineClass("de.cardcontact.scdp.gp.ApplicationFactory");
defineClass("de.cardcontact.scdp.js.JsX509");
defineClass("de.cardcontact.scdp.js.JsCRL");
defineClass("de.cardcontact.scdp.xmldsig.JsXMLSignature");
defineClass("de.cardcontact.scdp.js.JsASN1");
defineClass("de.cardcontact.scdp.js.JsKeyStore");
defineClass("de.cardcontact.scdp.js.JsCardFile");
defineClass("de.cardcontact.scdp.js.JsIsoSecureChannel");
defineClass("de.cardcontact.scdp.js.JsOCSPQuery");
defineClass("de.cardcontact.scdp.js.JsLDAP");
defineClass("de.cardcontact.scdp.js.JsSOAPConnection");
defineClass("de.cardcontact.scdp.js.JsURLConnection");
defineClass("de.cardcontact.scdp.cms.JsCMSSignedData");
defineClass("de.cardcontact.scdp.cms.JsCMSEnvelopedData");
defineClass("de.cardcontact.scdp.cms.JsCMSGenerator");
defineClass("de.cardcontact.scdp.pkcs11.JsPKCS11Provider");
defineClass("de.cardcontact.scdp.pkcs11.JsPKCS11Session");
defineClass("de.cardcontact.scdp.pkcs11.JsPKCS11Object");
defineClass("de.cardcontact.scdp.js.JsScript");

if (GPSystem.mapFilename("scsh/oid/oid.js")) {
	load("scsh/oid/oid.js");
}

switch(getPlatformID()) {
	case 4:
		defineClass("org.openscdp.scriptingserver.js.JsHttpRequest");
		defineClass("org.openscdp.scriptingserver.js.JsHttpResponse");
		defineClass("org.openscdp.scriptingserver.js.JsHttpSession");

		// The ScriptingServer does not have a print() method, so we
		// create a dummy using GPSystem.trace()
		var print = function() {
			for (var i = 0; i < arguments.length; i++) {
				if (arguments[i] == null) {
					GPSystem.trace("null");
				} else {
					GPSystem.trace(arguments[i]);
				}
			}
		}

		var startupscript = GPSystem.mapFilename("apps/startup.js", GPSystem.USR);
		var startupscriptfo = new java.io.File(startupscript);
		if (!startupscriptfo.exists()) {
			startupscript = GPSystem.mapFilename("apps/startup.js", GPSystem.SYS);
		}

		if (startupscript) {
			GPSystem.trace("Running " + startupscript);
			load(startupscript);
		}

		var __ScriptingServer = true;
		break;
	case 2:
		defineClass("de.cardcontact.scdp.cardsim.JsCardSimulationAdapter");
		defineClass("de.cardcontact.scdp.scsh3.OutlineNode");
		defineClass("de.cardcontact.scdp.scsh3.Dialog");
		defineClass("de.cardcontact.scdp.scsh3.AccessTerminal");
		defineClass("de.cardcontact.scdp.scsh3.Task");
		break;
}

GPSystem.trace("config.js processed...");
