'use strict';
// SMTP client object and class. This allows for every part of the client
// protocol to be hooked for different levels of control, such as
// smtp_forward and smtp_proxy queue plugins.

var events = require('events');
var util = require('util');
var generic_pool = require('generic-pool');
var line_socket = require('./line_socket');
var logger = require('./logger');
var uuid = require('./utils').uuid;
var utils = require('./utils');
var config = require('./config');
var tls_socket = require('./tls_socket');
var ipaddr      = require('ipaddr.js');
var constants = require('./constants')
var DSN = require('./dsn');

var smtp_regexp = /^([0-9]{3})([ -])(.*)/;
var STATE = {
    IDLE: 1,
    ACTIVE: 2,
    RELEASED: 3,
    DESTROYED: 4,
    SHUTDOWN: 5,
};

function SMTPClient(port, host, connect_timeout, idle_timeout, max_mails) {
    events.EventEmitter.call(this);
    this.uuid = uuid();
    this.connect_timeout = parseInt(connect_timeout) || 30;
    this.socket = line_socket.connect(port, host);
    this.socket.setTimeout(this.connect_timeout * 1000);
    this.socket.setKeepAlive(true);
    this.state = STATE.IDLE;
    this.command = 'greeting';
    this.response = [];
    this.connected = false;
    this.authenticated = false;
    this.auth_capabilities = [];
    this.mails_sent = 0;
    this.max_sent_mails = max_mails || 0;

    var client = this;

    var key = config.get('tls_key.pem', 'binary');
    var cert = config.get('tls_cert.pem', 'binary');
    var tls_options = (key && cert) ? { key: key, cert: cert } : {};
    this.tls_config = tls_socket.load_tls_ini();
    var config_options = ['ciphers','requestCert','rejectUnauthorized'];

    for (var i = 0; i < config_options.length; i++) {
        var opt = config_options[i];
        if (this.tls_config.main[opt] === undefined) { continue; }
        tls_options[opt] = this.tls_config.main[opt];
    }

    this.socket.on('line', function (line) {
        client.emit('server_protocol', line);
        var matches = smtp_regexp.exec(line);
        if (!matches) {
            client.emit('error', client.uuid + ': Unrecognised response from upstream server: ' + line);
            client.destroy();
            return;
        }

        var code = matches[1];
        var cont = matches[2];
        var msg = matches[3];

        client.response.push(msg);
        if (cont !== ' ') {
            return;
        }

        if (client.command === 'auth') {
            if (code.match(/^3/) && cont === 'VXNlcm5hbWU6') {
                client.emit('auth_username');
                return;
            }
            else if (code.match(/^3/) && cont === 'UGFzc3dvcmQ6') {
                client.emit('auth_password');
                return;
            }
        }

        if (client.command === 'ehlo') {
            if (code.match(/^5/)) {
                // Handle fallback to HELO if EHLO is rejected
                client.emit('greeting', 'HELO');
                return;
            }
            client.emit('capabilities');
            if (client.command !== 'ehlo') {
                return;
            }
        }
        if (client.command === 'xclient' && code.match(/^5/)) {
            // XCLIENT command was rejected (no permission?)
            // Carry on without XCLIENT
            client.command = 'helo';
        }
        else if (code.match(/^[45]/)) {
            client.emit('bad_code', code, client.response.join(' '));
            if (client.state !== STATE.ACTIVE) {
                return;
            }
        }
        switch (client.command) {
            case 'xclient':
                client.xclient = true;
                client.emit('xclient', 'EHLO');
                break;
            case 'starttls':
                this.upgrade(tls_options);
                break;
            case 'greeting':
                client.connected = true;
                client.emit('greeting', 'EHLO');
                break;
            case 'ehlo':
                client.emit('helo');
                break;
            case 'helo':
            case 'mail':
            case 'rcpt':
            case 'data':
            case 'dot':
            case 'rset':
            case 'auth':
                client.emit(client.command);
                break;
            case 'quit':
                client.emit('quit');
                client.destroy();
                break;
            default:
                throw new Error("Unknown command: " + client.command);
        }
    });

    this.socket.on('connect', function () {
        // Remove connection timeout and set idle timeout
        client.socket.setTimeout(((idle_timeout) ? idle_timeout : 300) * 1000);
        client.remote_ip = ipaddr.process(client.socket.address()).toString();
    });

    var closed = function (msg) {
        return function (error) {
            if (!error) {
                error = '';
            }

            var errMsg = '['+ client.uuid + '] SMTP connection ' + msg + ' ' + error;

            if ([STATE.ACTIVE].indexOf(client.state) > -1)
                client.closed_while_active = true;

            switch (client.state) {
                case STATE.ACTIVE:
                case STATE.IDLE:
                case STATE.RELEASED:
                    client.destroy();
                    break;
                default:
            }

            logger.logdebug('[smtp_client_pool] ' + errMsg + ' (state=' + client.state + ')');

            if (client.closed_while_active) {
                if (error instanceof Error)
                    client.emit('error', errMsg);
                else if (!error && msg == 'closed') { // we skip when error == true because we already handled that case above
                    errMsg = '['+ client.uuid + '] Remote party abruptly terminated the connection';
                    client.emit('error', errMsg);
                }
            }
        };
    };

    this.socket.on('error',   closed('errored'));
    this.socket.on('timeout', closed('timed out'));
    this.socket.on('close',   closed('closed'));
    this.socket.on('end',     closed('ended'));
}

util.inherits(SMTPClient, events.EventEmitter);

SMTPClient.prototype.send_command = function (command, data) {
    var line = (command === 'dot') ? '.' : command + (data ? (' ' + data) : '');
    this.emit('client_protocol', line);
    this.command = command.toLowerCase();
    this.response = [];
    this.socket.write(line + "\r\n");
};

SMTPClient.prototype.start_data = function (data) {
    this.response = [];
    this.command = 'dot';
    data.pipe(this.socket, { dot_stuffing: true, ending_dot: true, end: false });
};

SMTPClient.prototype.release = function () {
    if (!this.connected || this.command === 'data' || this.command === 'mailbody') {
        // Destroy here, we can't reuse a connection that was mid-data.
        this.destroy();
        return;
    }

    logger.logdebug('[smtp_client_pool] ' + this.uuid + ' resetting, state=' + this.state);
    if (this.state === STATE.DESTROYED) {
        return;
    }
    this.state = STATE.RELEASED;
    this.removeAllListeners('greeting');
    this.removeAllListeners('capabilities');
    this.removeAllListeners('xclient');
    this.removeAllListeners('helo');
    this.removeAllListeners('mail');
    this.removeAllListeners('rcpt');
    this.removeAllListeners('data');
    this.removeAllListeners('dot');
    this.removeAllListeners('rset');
    this.removeAllListeners('auth');
    this.removeAllListeners('client_protocol');
    this.removeAllListeners('server_protocol');
    this.removeAllListeners('error');
    this.removeAllListeners('bad_code');

    this.on('bad_code', function (code, msg) {
        this.destroy();
    });

    this.on('rset', function () {
        logger.logdebug('[smtp_client_pool] ' + this.uuid + ' releasing, state=' + this.state);
        if (this.state === STATE.DESTROYED) {
            return;
        }
        this.state = STATE.IDLE;
        this.removeAllListeners('client_protocol');
        this.removeAllListeners('server_protocol');
        this.removeAllListeners('rset');
        this.removeAllListeners('bad_code');
        this.pool.release(this);
    });

    this.send_command('RSET');
};

SMTPClient.prototype.shutdown = function () {
    if (!this.connected || this.command === 'data' || this.command === 'mailbody') {
        // Destroy here, we can't reuse a connection that was mid-data.
        this.destroy();
        return;
    }

    logger.logdebug('[smtp_client_pool] ' + this.uuid + ' shutting down, state=' + this.state);
    if (this.state === STATE.DESTROYED) {
        return;
    }

    this.state = STATE.SHUTDOWN;
    this.removeAllListeners('greeting');
    this.removeAllListeners('capabilities');
    this.removeAllListeners('xclient');
    this.removeAllListeners('helo');
    this.removeAllListeners('mail');
    this.removeAllListeners('rcpt');
    this.removeAllListeners('data');
    this.removeAllListeners('dot');
    this.removeAllListeners('rset');
    this.removeAllListeners('auth');
    this.removeAllListeners('error');
    this.removeAllListeners('bad_code');
    this.removeAllListeners('rset');

    this.on('bad_code', function (code, msg) {
        this.destroy();
    });

    this.on('quit', function () {
        logger.logdebug('[smtp_client_pool] ' + this.uuid + ' shutting down (on quit), state=' + this.state);
        if (this.state === STATE.DESTROYED) {
            return;
        }
        this.removeAllListeners('quit');
        this.removeAllListeners('client_protocol');
        this.removeAllListeners('server_protocol');
        this.removeAllListeners('bad_code');
        this.destroy();
    });

    this.send_command('QUIT');
};

SMTPClient.prototype.destroy = function () {
    if (this.state !== STATE.DESTROYED) {
        this.pool.destroy(this);
    }
};

SMTPClient.prototype.is_dead_sender = function (plugin, connection) {
    if (connection.transaction) { return false; }

    // This likely means the sender went away on us, cleanup.
    connection.logwarn(plugin, "transaction went away, releasing smtp_client");
    this.release();
    this.call_next(constants['denysoft'], 'smtpclient said transaction went away');
    return true;
};

// Separate pools are kept for each set of server attributes.
exports.get_pool = function (server, port, host, connect_timeout, pool_timeout, max, max_mails) {
    port = port || 25;
    host = host || 'localhost';
    connect_timeout = (connect_timeout === undefined) ? 30 : connect_timeout;
    pool_timeout = (pool_timeout === undefined) ? 300 : pool_timeout;
    max_mails = max_mails || 0;

    var name = port + ':' + host + ':' + pool_timeout;
    if (!server.notes.pool) {
        server.notes.pool = {};
    }
    if (!server.notes.pool[name]) {
        var pool = generic_pool.Pool({
            name: name,
            create: function (callback) {
                var smtp_client = new SMTPClient(port, host, connect_timeout, null, max_mails);
                logger.logdebug('[smtp_client_pool] uuid=' + smtp_client.uuid + ' host=' + host
                    + ' port=' + port + ' pool_timeout=' + pool_timeout + ' max_mails=' + max_mails + ' created');
                callback(null, smtp_client);
            },
            destroy: function(smtp_client) {
                if (smtp_client.state === STATE.IDLE && !smtp_client.want_to_die) { // destroy had fallen upon us probably because of timeout
                    smtp_client.want_to_die = true; // better safe than sorry
                    logger.logdebug('[smtp_client_pool] ' + smtp_client.uuid + ' is asked to be shutdown, state=' + smtp_client.state);
                    smtp_client.shutdown();
                }

                logger.logdebug('[smtp_client_pool] ' + smtp_client.uuid + ' destroyed, state=' + smtp_client.state);
                smtp_client.state = STATE.DESTROYED;
                smtp_client.socket.destroy();
                // Remove pool object from server notes once empty
                var size = pool.getPoolSize();
                if (size === 0) {
                    delete server.notes.pool[name];
                }
            },
            max: max || 1000,
            idleTimeoutMillis: pool_timeout * 1000,
            reapIntervalMillis: 1000,
            log: function (str, level) {
                level = (level === 'verbose') ? 'debug' : level;
                logger['log' + level]('[smtp_client_pool] [' + name + '] ## ' + str);
            }
        });

        var acquire = pool.acquire;
        pool.acquire = function (callback, priority) {
            var callback_wrapper = function (err, smtp_client) {
                smtp_client.pool = pool;
                smtp_client.state = STATE.ACTIVE;
                callback(err, smtp_client);
            };
            acquire.call(pool, callback_wrapper, priority);
        };
        server.notes.pool[name] = pool;
    }
    return server.notes.pool[name];
};

// Get a smtp_client for the given attributes.
exports.get_client = function (server, callback, port, host, connect_timeout, pool_timeout, max) {
    var pool = exports.get_pool(server, port, host, connect_timeout, pool_timeout, max);
    pool.acquire(callback);
};

// Get a smtp_client for the given attributes and set up the common
// config and listeners for plugins. This is what smtp_proxy and
// smtp_forward have in common.
exports.get_client_plugin = function (plugin, connection, config, callback) {
    var c = config;
    // Merge in authentication settings from smtp_forward/proxy.ini if present
    // FIXME: config.auth could be changed when API isn't frozen
    if (c.auth_type || c.auth_user || c.auth_pass) {
        c.auth = {
            type: c.auth_type,
            user: c.auth_user,
            pass: c.auth_pass
        }
    }

    var cfg_error_action = c.error_action && constants[c.error_action.toLowerCase()];

    var pool = exports.get_pool(connection.server, c.port, c.host,
                                c.connect_timeout, c.timeout, c.max_connections, c.max_mails);
    pool.acquire(function (err, smtp_client) {
        connection.logdebug(plugin, 'Got smtp_client: ' + smtp_client.uuid);
        connection.logdebug(plugin, 'Got smtp_client [sent: ' + smtp_client.mails_sent + '/' + smtp_client.max_sent_mails + '] uuid: ' + smtp_client.uuid);

        var secured = false;

        smtp_client.call_next = function (retval, msg) {
            if (this.next && !smtp_client.next_called) {
                var next = this.next;
                delete this.next;
                smtp_client.next_called = true;
                next(retval, msg);
            }
        };

        smtp_client.on('client_protocol', function (line) {
            plugin.logprotocol('SC ['+ smtp_client.uuid +'] C: ' + line);
        });

        smtp_client.on('server_protocol', function (line) {
            plugin.logprotocol('SC ['+ smtp_client.uuid +'] S: ' + line);
        });

        var helo = function (command) {
            if (smtp_client.xclient) {
                smtp_client.send_command(command, connection.hello_host);
            }
            else {
                smtp_client.send_command(command, plugin.config.get('me'));
            }
        };
        smtp_client.on('greeting', helo);
        smtp_client.on('xclient', helo);

        smtp_client.on('capabilities', function () {
            var on_secured = function () {
                secured = true;
                smtp_client.emit('greeting', 'EHLO');
            };
            for (var line in smtp_client.response) {
                if (smtp_client.response[line].match(/^XCLIENT/)) {
                    if (!smtp_client.xclient) {
                        smtp_client.send_command('XCLIENT', 'ADDR=' + connection.remote_ip);
                        return;
                    }
                }

                if (smtp_client.response[line].match(/^STARTTLS/) && !secured) {
                    if (!(c.host in smtp_client.tls_config.no_tls_hosts) &&
                        !(smtp_client.remote_ip in smtp_client.tls_config.no_tls_hosts) &&
                        c.enable_tls)
                    {
                        smtp_client.socket.on('secure', on_secured);
                        smtp_client.send_command('STARTTLS');
                        return;
                    }
                }

                var auth_matches = smtp_client.response[line].match(/^AUTH (.*)$/);
                if (auth_matches) {
                    smtp_client.auth_capabilities = [];
                    auth_matches = auth_matches[1].split(' ');
                    for (var i = 0; i < auth_matches.length; i++) {
                        smtp_client.auth_capabilities.push(auth_matches[i].toLowerCase());
                    }
                }
            }
        });

        smtp_client.on('helo', function () {
            if (!config.auth || smtp_client.authenticated) {
                if (smtp_client.is_dead_sender(plugin, connection)) {
                    return;
                }
                smtp_client.send_command('MAIL', 'FROM:' + connection.transaction.mail_from);
                return;
            }

            if (config.auth.type === null || typeof(config.auth.type) === 'undefined') { return; } // Ignore blank
            var auth_type = config.auth.type.toLowerCase();
            if (smtp_client.auth_capabilities.indexOf(auth_type) === -1) {
                throw new Error("Auth type \"" + auth_type + "\" not supported by server (supports: " + smtp_client.auth_capabilities.join(',') + ")");
            }
            switch (auth_type) {
                case 'plain':
                    if (!config.auth.user || !config.auth.pass) {
                        throw new Error("Must include auth.user and auth.pass for PLAIN auth.");
                    }
                    logger.logdebug('[smtp_client_pool] uuid=' + smtp_client.uuid + ' authenticating as "' + config.auth.user + '"');
                    smtp_client.send_command('AUTH',
                        'PLAIN ' + utils.base64(config.auth.user + "\0" + config.auth.user + "\0" + config.auth.pass) );
                    break;
                case 'cram-md5':
                    throw new Error("Not implemented");
                default:
                    throw new Error("Unknown AUTH type: " + auth_type);
            }
        });

        smtp_client.on('auth', function () {
            if (smtp_client.is_dead_sender(plugin, connection)) {
                return;
            }
            smtp_client.authenticated = true;
            smtp_client.send_command('MAIL', 'FROM:' + connection.transaction.mail_from);
        });

        smtp_client.on('error', function (msg) {
            plugin.logwarn(msg, connection);
            smtp_client.call_next(cfg_error_action, DSN.sys_not_accepting_mail('backend said: ' + msg));
        });

        if (smtp_client.connected) {
            if (smtp_client.xclient) {
                smtp_client.send_command('XCLIENT', 'ADDR=' + connection.remote_ip);
            }
            else {
                smtp_client.emit('helo');
            }
        }

        callback(err, smtp_client);
    });
};
