/**
 *  ---------
 * |.##> <##.|  SmartCard-HSM Support Scripts
 * |#       #|
 * |#       #|  Copyright (c) 2011-2012 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  ---------
 *
 * Consult your license package for usage terms and conditions.
 *
 * @fileoverview SmartCard-HSM Management Server
 */

if (GPSystem.mapFilename("build.version")) {
	load("build.version");
} else {
	VERSION = "snapshot";
}
GPSystem.log(GPSystem.INFO, "sc-hsm-mgr.SharedScope", "Version is " + VERSION);

// Source configuration from etc/configuration.js

var Config = {};
if (GPSystem.mapFilename("etc/configuration.js")) {
	load("etc/configuration.js");
} else {
	GPSystem.log(GPSystem.INFO, "sc-hsm-mgr.SharedScope", "Not sourcing etc/configuration.js");
}


// --- Global settings ---

var ApplicationServer = require('scsh/srv-cc1/ApplicationServer').ApplicationServer;

if (Config.serverURL) {
	ApplicationServer.instance.setServerURL(Config.serverURL);
}

function handleRequest(req, res) {
	ApplicationServer.instance.handleRequest(req, res);
}

function performCardUpdate(session, pathInfo) {
	ApplicationServer.instance.performCardUpdate(session, pathInfo);
}


// --- HSM section ---

var HSMService = require('scsh/srv-cc1/HSMService').HSMService;

var hsm = new HSMService();

ApplicationServer.instance.registerService("hsm", null, hsm, hsm );

var HSMRESTService = require('HSMRESTService').HSMRESTService;

var srv = new HSMRESTService(hsm);

ApplicationServer.instance.registerServiceForURL("api", { name: "SmartCard-HSM Service", description: "SmartCard-HSM REST Service", restHandler: srv}, 8080);


