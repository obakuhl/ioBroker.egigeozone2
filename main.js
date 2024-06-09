/**
 *
 * egigeozone2 adapter
 * This Adapter is based on the geofency adapter of ccu.io
 *
 */

/* jshint -W097 */
/* jshint strict: false */
/* jslint node: true */
'use strict';

const utils = require('@iobroker/adapter-core'); // Get common adapter utils
const adapterName = require('./package.json').name.split('.').pop();
const EgiGeoZoneWebServer = require('@iobroker/webserver');
const url = require('node:url');

let webServer =  null;
let store = null;
let activateServer = false;
let adapter;
const objectsInitialized = {};

function startAdapter(options) {
    options = options || {};
    Object.assign(options, {
        name: adapterName,
        unload: callback => {
            try {
                webServer.close(() => {
                    adapter && adapter.log && adapter.log.info(`http${webServer.settings.secure ? 's' : ''} server terminated on port ${webServer.settings.port}`);
                    callback();
                });
            } catch (e) {
                callback();
            }
        },
        ready: () => main(),
        message: msg => processMessage(msg),
    });
    adapter = new utils.Adapter(options);

    return adapter;
}

function main() {
    adapter.setState('info.connection', false, true);
    activateServer = adapter.config.activate_server !== undefined ? adapter.config.activate_server: true;

    if (activateServer) {
        adapter.config.port = parseInt(adapter.config.port, 10);
        if (adapter.config.secure) {
        // Load certificates
        adapter.getCertificates((err, certificates, leConfig) => {
            adapter.config.certificates = certificates;
            adapter.config.leConfig = leConfig;
            webServer = initWebServer(adapter.config);
        });
    	} else {
            webServer = initWebServer(adapter.config);
        }
    } else {
        adapter.setState('info.connection', true, true);
    }
}

function initWebServer(settings) {
    const server = {app: null, server: null, io: null, settings};

    settings.port = parseInt(settings.port, 10) || 0;

    if (settings.port) {
        if (settings.secure && !settings.certificates) {
            return null;
        }

        adapter.getPort(
            settings.port,
            !settings.bind || settings.bind === '0.0.0.0' ? undefined : settings.bind || undefined,
            async port => {
                if (parseInt(port, 10) !== settings.port && !adapter.config.findNextPort) {
                    adapter.log.error(`port ${settings.port} already in use`);
                    return adapter.terminate ? adapter.terminate(utils.EXIT_CODES.ADAPTER_REQUESTED_TERMINATION) : process.exit(utils.EXIT_CODES.ADAPTER_REQUESTED_TERMINATION);
                }

                settings.port = port;

                try {
		    if (settings.auth) {
                	const webserver = new EgiGeoZoneWebServer.WebServer({app: requestProcessorAuth, adapter, secure: adapter.config.secure});
                    	server.server = await webserver.init();
		    } else {
		        const webserver = new EgiGeoZoneWebServer.WebServer({app: requestProcessor, adapter, secure: adapter.config.secure});
                    	server.server = await webserver.init();
		    }
                } catch (err) {
                    adapter.log.error(`Cannot create webserver: ${err}`);
                    adapter.terminate ? adapter.terminate(utils.EXIT_CODES.ADAPTER_REQUESTED_TERMINATION) : process.exit(utils.EXIT_CODES.ADAPTER_REQUESTED_TERMINATION);
                    return;
                }
                if (!server.server) {
                    adapter.log.error(`Cannot create webserver`);
                    adapter.terminate ? adapter.terminate(utils.EXIT_CODES.ADAPTER_REQUESTED_TERMINATION) : process.exit(utils.EXIT_CODES.ADAPTER_REQUESTED_TERMINATION);
                    return;
                }

                let serverListening = false;
                server.server.on('error', e => {
                    if (e.toString().includes('EACCES') && port <= 1024) {
                        adapter.log.error(
                            `node.js process has no rights to start server on the port ${port}.\n` +
                                'Do you know that on linux you need special permissions for ports under 1024?\n' +
                                'You can call in shell following scrip to allow it for node.js: "iobroker fix"'
                        );
                    } else {
                        adapter.log.error(`Cannot start server on ${settings.bind || '0.0.0.0'}:${port}: ${e}`);
                    }
                    if (!serverListening) {
                        adapter.terminate ? adapter.terminate(utils.EXIT_CODES.ADAPTER_REQUESTED_TERMINATION) : process.exit(utils.EXIT_CODES.ADAPTER_REQUESTED_TERMINATION);
                    }
                });

                // Start the web server
                server.server.listen(settings.port, (!settings.bind || settings.bind === '0.0.0.0') ? undefined : settings.bind || undefined, () => {
			adapter.setState('info.connection', true, true);
			serverListening = true;
                });

		adapter.log.info(`http${settings.secure ? 's' : ''} server listening on port ${port}`);
            }
        );
    } else {
        adapter.log.error('port missing');
        adapter.terminate ? adapter.terminate(utils.EXIT_CODES.ADAPTER_REQUESTED_TERMINATION) : process.exit(utils.EXIT_CODES.ADAPTER_REQUESTED_TERMINATION);
    }

    return server;
}

//auth
function requestProcessorAuth(req, res) {

    adapter.log.debug('Authorization necessary');
	
    const checkUser = adapter.config.user;
    const checkPass = adapter.config.pass;
	
    // If they pass in a basic auth credential it'll be in a header called "Authorization" (note NodeJS lowercases the names of headers in its request object)
    const auth2 = req.headers.authorization;  // auth is in base64(username:password)  so we need to decode the base64
    adapter.log.debug(`Authorization Header is: ${JSON.stringify(auth2)}`);
	
    let requestValid = true;
    if (checkUser && checkPass) {
	if (!auth2) {
	    adapter.log.warn('Authorization Header missing but user/pass defined');
	    requestValid = false;
	} else {
	    const tmp = auth2.split(' ');   // Split on a space, the original auth looks like  "Basic Y2hhcmxlczoxMjM0NQ==" and we need the 2nd part
	    const plainAuth = Buffer.from(tmp[1], 'base64').toString(); // create a buffer and tell it the data coming in is base64
		
	    adapter.log.debug(`Decoded Authorization ${plainAuth}`);
	    // At this point plainAuth = "username:password"
	    const [username, password] = plainAuth.split(':');      // split on a ':'
	    if (username !== checkUser || password !== checkPass) {
		adapter.log.warn('User credentials invalid');
		requestValid = false;
	    }
	}
    }
    if (!requestValid) {
	res.statusCode = 401;
	res.end();
	return;
    }

    if (req.method === 'GET') {
        adapter.log.debug(`request url: ${req.url}`);
        const parsedUrl = url.parse(req.url, true);

        const user = (parsedUrl.pathname.slice(1)).replace(adapter.FORBIDDEN_CHARS, '_').replace(/\s|\./g, '_');

	(async() => {
            try {
		const reqData = parsedUrl.query;
		//log analyzed data
		adapter.log.debug(`Analyzed request data: ${JSON.stringify(reqData)}`);		
		await handleRequest(user, reqData);
            } catch (err) {
		adapter.log.info(`Could not process request for user ${user}: ${err}`);
		res.writeHead(500);
		res.write('Request error');
		res.end();
		return;
            }
            //log requested user
            adapter.log.debug(`request user: ${user}`);
	
            res.writeHead(200);
            res.write("OK");
            res.end();
	})();
    } else {
	res.writeHead(500);
	res.write("Request error");
	res.end();
    }
}

//non auth
function requestProcessor(req, res) {
	
    adapter.log.debug('No authorization necessary');

    if (req.method === 'GET') {
        adapter.log.debug(`request url: ${req.url}`);
        const parsedUrl = url.parse(req.url, true);

        const user = (parsedUrl.pathname.slice(1)).replace(adapter.FORBIDDEN_CHARS, '_').replace(/\s|\./g, '_');

	(async() => {
            try {
		const reqData = parsedUrl.query;
		//log analyzed data
		adapter.log.debug(`Analyzed request data: ${JSON.stringify(reqData)}`);		
		await handleRequest(user, reqData);
            } catch (err) {
		adapter.log.info(`Could not process request for user ${user}: ${err}`);
		res.writeHead(500);
		res.write('Request error');
		res.end();
		return;
            }
            //log requested user
            adapter.log.debug(`request user: ${user}`);
	
            res.writeHead(200);
            res.write("OK");
            res.end();
	})();
    } else {
	res.writeHead(500);
	res.write("Request error");
	res.end();
    }
}

async function handleRequest(user, reqData) {
    if (adapter.config.ignoreLeaving && reqData.entry == "0") {
        adapter.log.debug("Ignoring leaving message (as configured)");
        return;
    }

    const msg = (reqData.entry == "1") ? "entered" : "left";
    adapter.log.info(`Location changed: ${user} ${msg} ${reqData.name}`);

    // create states
    if (!objectsInitialized[user]) {
	await createObjects(user, reqData);
	objectsInitialized[user] = true;
    }
    await setStates(user, reqData);
    await setAtHome(user, reqData);
}

const stateAtHomeCount = 'atHomeCount';
const stateAtHome = 'atHome';

async function setStates(user, reqData) {
    let entry = reqData.entry;
    if (entry !== undefined) {
        entry = !!parseInt(entry, 10);
    }
	
    adapter.setState(user, {val: entry, ack: true});
	
    const ts = adapter.formatDate(new Date(reqData.date), 'YYYY-MM-DD hh:mm:ss');

    if (reqData.entry == "1")
    {		
	await adapter.setStateAsync(`${user}.changed`, {val: ts, ack: true});
	await adapter.setStateAsync(`${user}.location`, {val: reqData.name, ack: true});
	await adapter.setStateAsync(`${user}.lastLatitude`, {val: reqData.latitude, ack: true});
	await adapter.setStateAsync(`${user}.lastLongitude`, {val: reqData.longitude, ack: true});
	await adapter.setStateAsync(`${user}.json`, JSON.stringify(reqData), true);
    } else {
	await adapter.setStateAsync(`${user}.changed`, {val: ts, ack: true});
	await adapter.setStateAsync(`${user}.location`, {val: "", ack: true});
    }
}

async function createObjects(user, reqData) {
    // create all Objects
    adapter.log.debug(`Creating objects for "${user}"`);
    await adapter.extendObjectAsync(user, {
	type: 'device',
	common: {name: user, role: 'state', type: 'boolean'}, //why boolean, it is a folder
	native: {name: user, device: reqData.device}
    });

    let obj = {
        type: 'state',
        common: {name: 'changed', read: true, write: false, role: 'date', type: 'string'},
        native: {user}
    };
    await adapter.extendObjectAsync(`${user}.changed`, obj);
    obj = {
        type: 'state',
        common: {name: 'location', read: true, write: false, role: 'location', type: 'string'},
        native: {user}
    };
    await adapter.extendObjectAsync(`${user}.location`, obj);	
    obj = {
        type: 'state',
        common: {name: 'lastLatitude', read: true, write: false, role: 'value.gps.latitude', type: 'string'},
        native: {user}
    };
    await adapter.extendObjectAsync(`${user}.lastLatitude`, obj);
    obj = {
        type: 'state',
        common: {name: 'lastLongitude', read: true, write: false, role: 'value.gps.longitude', type: 'string'},
        native: {user}
    };
    await adapter.extendObjectAsync(`${user}.lastLongitude`, obj);
    obj = {
        type: 'state',
        common: {name: 'json', read: true, write: false, role: 'json', type: 'string'},
        native: {user}
    };
    await adapter.extendObjectAsync(`${user}.json`, obj);
}

async function setAtHome(userName, reqData) {
    if (reqData.name.toLowerCase().trim() !== adapter.config.atHome.toLowerCase().trim()) {
        return;
    }
    let atHomeCount;
    let atHome;

    const _stateAtHomeCount = await adapter.getStateAsync(stateAtHomeCount);
    atHomeCount = _stateAtHomeCount ? _stateAtHomeCount.val : 0;

    const _stateAtHome = await adapter.getStateAsync(stateAtHome);
    atHome = _stateAtHome ? (_stateAtHome.val ? JSON.parse(_stateAtHome.val) : []) : [];

    let entry = reqData.entry;
    if (entry !== undefined) {
        entry = !!parseInt(entry, 10);
    }

    if (entry) {
        if (!atHome.includes(userName)) {
            atHome.push(userName);
            await adapter.setStateAsync(stateAtHome, JSON.stringify(atHome), true);
        }
    } else {
        const idx = atHome.indexOf(userName);
        if (idx !== -1) {
            atHome.splice(idx, 1);
            await adapter.setStateAsync(stateAtHome, JSON.stringify(atHome), true);
        }
    }
    if (atHomeCount !== atHome.length) {
        await adapter.setStateAsync(stateAtHomeCount, atHome.length, true);
    }
}

async function processMessage(message) {
    if (!message || !message.message.user || !message.message.data) {
        return;
    }

    adapter.log.info(`Message received = ${JSON.stringify(message)}`);

    try {
        await handleRequest(message.message.user, message.message.data);
    } catch (err) {
        adapter.log.info(`Could not process request for user ${message.message.user}: ${err}`);
    }
}

// If started as allInOne/compact mode => return function to create instance
if (module && module.parent) {
    module.exports = startAdapter;
} else {
    // or start the instance directly
    startAdapter();
}
