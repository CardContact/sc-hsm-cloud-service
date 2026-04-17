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

var TestRunner = require("scsh/testing/TestRunner").TestRunner;
var TestGroup = require("scsh/testing/TestGroup").TestGroup;
var TestProcedure = require("scsh/testing/TestProcedure").TestProcedure;

var TestAdapter = require("TestAdapter").TestAdapter;
var CVC = require("scsh/eac/CVC").CVC;


var param = {};
param.crypto = new Crypto();
param.url = "http://localhost:8080/se";


var testRunner = new TestRunner("SmartCard-HSM Clout Service Test Suite");

testRunner.addTestGroupFromXML("tg_get.xml", param);
testRunner.addTestGroupFromXML("tg_signhash.xml", param);

print("Test-Suite loaded...");
