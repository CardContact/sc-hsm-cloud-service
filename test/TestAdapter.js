/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|
 * |#       #|  Copyright (c) 2026 CardContact Systems GmbH
 * |'##> <##'|  32429 Minden, Germany (www.cardcontact.de)
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
 * @fileoverview Script to load all tests for the sc-hsm-cloud-service
 */



/**
 * Class implementing basic access functions for testing the SmartCard-HSM Cloud Service
 * @constructor
 * @pararm {String} url the base server URL
 */
function TestAdapter(url) {
	this.url = url;
}

exports.TestAdapter = TestAdapter;



/**
 * Perform GET
 *
 * @type Object
 * @return JSON object with response from server
 */
TestAdapter.prototype.get = function(path) {

	var url = new URLConnection(this.url + path);
	url.addHeaderField("Accept", "application/json");

	var result = url.get();

	GPSystem.trace(result);

	return JSON.parse(result);
}



/**
 * Perform POST
 *
 * @type Object
 * @return JSON object with response from server
 */
TestAdapter.prototype.post = function(path, req) {

	var url = new URLConnection(this.url + path);
	url.addHeaderField("Accept", "application/json");
	url.addHeaderField("Content-Type", "application/json");

	var result = url.post(JSON.stringify(req));

	GPSystem.trace(result);

	return JSON.parse(result);
}
