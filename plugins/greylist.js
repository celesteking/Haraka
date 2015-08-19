// Greylisting Haraka plugin

var version = '0.1.2';

var util = require('util');
var redis = require('redis');
var Q = require('q');
var DSN = require('Haraka/dsn');
var net_utils = require('Haraka/net_utils');
var utils = require('Haraka/utils');
var Address   = require('Haraka/address').Address;
var ipaddr = require('ipaddr.js');

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
exports.register = function(next){
    var plugin = this;

    plugin.load_config();
    plugin.load_config_lists();

    this.register_hook('init_master',  'redis_onInit');
    this.register_hook('init_child',   'redis_onInit');
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
exports.load_config = function () {
    var plugin = this;

    plugin.cfg = plugin.config.get('greylist.ini', {
        booleans: [
            '+skip.dnswlorg',
            '-skip.mailspikewl'
        ]
    }, function(){ plugin.load_config(); });

    if (plugin.cfg.main.action.match(/learn/i))
        plugin.lognotice('Plugin running in LEARN mode. Nothing will be deferred or rejected.');
};

// Load various configuration lists
exports.load_config_lists = function() {
    var plugin = this;

    plugin.whitelist = {};
    plugin.list = {};

    function load_list (type, file_name) {
        plugin.whitelist[type] = {};

        // load config with a self-referential callback
        var list = plugin.config.get(file_name, 'list', function () {
            load_list(type, file_name);
        });

        // toLower when loading spends a fraction of a second at load time
        // to save millions of seconds during run time.
        for (var i = 0; i < list.length; i++) {
            plugin.whitelist[type][list[i].toLowerCase()] = true;
        }
        plugin.logdebug('whitelist {' + type + '} loaded from ' + file_name + ' with ' + list.length + ' entries');
    }

    function load_re (type, file_name) {
        // load config with a self-referential callback
        var list = plugin.config.get(file_name, 'list', function () {
            load_re(type, file_name);
        });

        var regex_list = utils.valid_regexes(list, file_name);

        plugin.whitelist[type] = new RegExp('^(' + regex_list.join('|') + ')$', 'i');
    }

    function load_ip_list (type, file_name) {
        plugin.whitelist[type] = [];

        var list = plugin.config.get(file_name, 'list', function () {
            load_ip_list(type, file_name);
        });

        for (var i = 0; i < list.length; i++) {
            try {
                var addr = list[i];
                if (addr.match(/\/\d+$/)) {
                    addr = ipaddr.parseCIDR(addr);
                } else {
                    addr = [ipaddr.parse(addr), 32];
                }

                plugin.whitelist[type].push(addr);
            } catch (e) {}
        }

        plugin.logdebug('whitelist {' + type + '} loaded from ' + file_name + ' with ' + plugin.whitelist[type].length + ' entries');
    }

    function load_config_list (type, file_name) {
        plugin.list[type] = plugin.config.get(file_name, 'list', function () {
            load_config_list(type, file_name);
        });

        plugin.logdebug('list {' + type + '} loaded from ' + file_name + ' with ' + plugin.list[type].length + ' entries');
    }

    load_list('mail', 'greylist.envelope.whitelist');
    load_list('rcpt', 'greylist.recipient.whitelist');
    load_ip_list('ip', 'greylist.ip.whitelist');

    load_config_list('dyndom', 'greylist.special.dynamic.domains');
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
exports.redis_onInit = function (next, server) {
    var plugin = this;

    if (plugin.redis) return next();

    var r_opts = {
    	//connect_timeout: 1000
    };

    var next_called;

    (plugin.redis = redis.createClient(plugin.cfg.redis.port, plugin.cfg.redis.host, r_opts))
        .on('error', function (err) {
            plugin.logerror("[gl] Redis error: " + err + '. Reconnecting...');
        })
        .on('ready', function(){
            plugin.loginfo('[gl] Redis connected to ' + plugin.redis.host + ':' + (plugin.redis.port ||0 ) +
                    '/' +  (plugin.cfg.redis.db || 0 ) + ' v' + plugin.redis.server_info.redis_version);

            if (plugin.cfg.redis.db) {
                plugin.redis.select(plugin.cfg.redis.db, function(){
                    if (!next_called) {
                        next_called = true;
                        return next();
                    }
                })
            } else if (!next_called) {
                next_called = true;
                return next();
            }
        });
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// We check for IP and envelope whitelist
exports.hook_mail = function(next, connection, params) {
    var plugin = this;
    var mail_from = params[0];

    // whitelist checks
    if (plugin.ip_in_list(connection.remote_ip)){ // check connecting IP

        plugin.loginfo(connection, 'Connecting IP was whitelisted via config');
        connection.transaction.results.add(plugin, {skip: 'config-whitelist(ip)'});

    } else if (plugin.addr_in_list('mail', mail_from.address().toLowerCase())){  // check envelope (email & domain)

        plugin.loginfo(connection, 'Envelope was whitelisted via config');
        connection.transaction.results.add(plugin, {skip: 'config-whitelist(envelope)'});

    } else {
        var why_skip = plugin.process_skip_rules(connection);

        if (why_skip) {
            plugin.loginfo(connection, 'Requested to skip the GL because skip rule matched: ' + why_skip);
            connection.transaction.results.add(plugin, {skip: 'requested(' + why_skip + ')'});
        }
    }

    return next();
};

//
exports.hook_rcpt_ok = function (next, connection, rcpt) {
    var plugin = this;
    var ctr = connection.transaction.results;
    var mail_from = connection.transaction.mail_from;

    if (plugin.should_skip_check(connection))
        return next();

    if (ctr.has(plugin, 'skip', 'special-sender')){ // asked to postpone till DATA
        plugin.loginfo(connection, 'skipping special sender (session)');
        return next();
    }

    if (plugin.was_whitelisted_in_session(connection)) {
        plugin.logdebug(connection, 'host already whitelisted in this session');
        return next();
    }

    if (plugin.addr_in_list('rcpt', rcpt.address().toLowerCase())) {  // check rcpt in whitelist (email & domain)
        plugin.loginfo(connection, 'RCPT was whitelisted via config');
        ctr.add(plugin, {skip: 'config-whitelist(recipient)'});
        return next();
    }

    return plugin.check_and_update_white(connection)
            .then(function(white_rec) {
                if (white_rec) {
                    plugin.logdebug(connection, 'host in WHITE zone');
                    ctr.add(plugin, { pass: 'whitelisted' });
                    ctr.push(plugin, {stats: { rcpt: white_rec }, stage: 'rcpt'});

                    return next();
                } else {
                    if (plugin.is_sender_special(mail_from)) { // postpone till DATA
                        ctr.add(plugin, {skip: 'special-sender', stage: 'rcpt' });
                        return next();
                    }

                    return plugin.process_tuple(connection, mail_from.address(), rcpt.address())
                            .then(function(white_promo_rec) {
                                plugin.loginfo(connection, 'host has been promoted to WHITE zone');

                                ctr.add(plugin, {pass: 'whitelisted' });
                                ctr.push(plugin, {stats: { rcpt: white_promo_rec}, stage: 'rcpt', event: 'promoted'});

                                return plugin.invoke_outcome_cb(next, true);
                            })
                            .fail(function(error){
                                if (error instanceof Error && error.notanerror) {
                                    plugin.logdebug(connection, 'host in GREY zone');

                                    ctr.add(plugin, {fail: 'greylisted'});
                                    ctr.push(plugin, {stats: { rcpt: error.record}, stage: 'rcpt'});

                                    return plugin.invoke_outcome_cb(next, false);
                                }

                                throw error;
                            })
                            .done();
                }
            })
            .fail(function(error){
                plugin.logerror(connection, 'Got error: ' + util.inspect(error));
                return next(DENYSOFT, DSN.sec_unspecified('Backend failure. Please, retry later or contact our support.'));
            })
            .done();
};

//
// Note: We process data hook only when asked by rcpt: results({skip: 'special-sender'})
//
exports.hook_data = function(next, connection){
    var plugin      = this;
    var ctr         = connection.transaction.results;
    var from_addr   = connection.transaction.mail_from.address();

    if (!connection.transaction.results.has(plugin, 'skip', 'special-sender'))
        return next();

    if (plugin.should_skip_check(connection))
        return next();

    plugin.logdebug(connection, 'Special sender handling requested. Proceeding...');

    // iterate over supplied rcpts, stopping if match is found
    return Q.any(connection.transaction.rcpt_to.map(function(rcpt){ return plugin.process_tuple(connection, from_addr, rcpt.address())}))
        .then(function (white_promo_rec) {
            plugin.loginfo(connection, 'host has been promoted to WHITE zone');
            ctr.add(plugin, {pass: 'whitelisted', stats: white_promo_rec, stage: 'data'});
            return plugin.invoke_outcome_cb(next, true);
        })
        .fail(function (error) {
            ctr.add(plugin, {fail: 'greylisted', stage: 'data' });
            return plugin.invoke_outcome_cb(next, false);
        })
        .done();
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Main GL engine that accepts tuple and returns matched record or a rejection.
exports.process_tuple = function (connection, sender, rcpt) {
    var plugin = this;

    var key = plugin.craft_grey_key(connection, sender, rcpt);

    return plugin.db_lookup(key)
            .then(function (record) {
                plugin.logdebug(connection, 'got record: ' + util.inspect(record));

                // { created: TS, updated: TS, lifetime: TTL, tried: Integer }
                var now = Date.now() / 1000;

                if (record &&
                        (record.created + plugin.cfg.period.black < now) &&
                        (record.created + record.lifetime >= now)) {
                    // Host passed greylisting
                    return plugin.promote_to_white(connection, record);
                }

                return plugin.update_grey(key, !record)
                        .then(function (created_record) {
                            var err = new Error('in black zone');
                            err.record = created_record || record;
                            err.notanerror = true;
                            throw err;
                        });
            })
            .fail(function (error) {
                if (error instanceof Error && error.what == 'db_error')
                    plugin.logwarn(connection, "got err from DB: " + util.inspect(error));
                throw error;
            });
};

// Checks if host is _white_. Updates stats if so.
exports.check_and_update_white = function (connection) {
    var plugin = this;
    var ctr = connection.transaction.results;

    var key = plugin.craft_white_key(connection);

    return plugin.db_lookup(key)
            .then(function (record) {
                if (record) {
                    if (record.updated + record.lifetime - 2 < Date.now() / 1000) { // race "prevention".
                        plugin.logerror(connection, "Mischief! Race condition triggered.");
                        throw new Error('drunkard');
                    }

                    return plugin.update_white_record(key, record);
                }

                return false;
            })
            .fail(function (error) {
                plugin.logwarn(connection, "got err from DB: " + util.inspect(error));
                throw error;
            });
};

// invokes next() depending on outcome param
exports.invoke_outcome_cb = function (next, is_whitelisted) {
    var plugin = this;

    if (is_whitelisted) {
        return next();
    } else {
        var action = plugin.cfg.main.action || 'defer';
        var text = plugin.cfg.main.text || '';

        if (action == 'learn') {
            return next();
        } else {
            var reject = (action == 'reject');
            return next(reject ? DENY : DENYSOFT, DSN.sec_unauthorized(text, reject ? '551' : '451'));
        }
    }
};

// Should we skip greylisting invokation altogether?
exports.should_skip_check = function(connection) {
    var plugin = this;
    var ctr = connection.transaction && connection.transaction.results;

    if (connection.relaying) {
        plugin.logdebug(connection, 'skipping GL for relaying host');
        ctr.add(plugin, {skip: 'relaying'});
        return true;
    }

    if (net_utils.is_private_ip(connection.remote_ip)) {
        connection.logdebug(plugin, 'skipping private IP: ' + connection.remote_ip);
        ctr.add(plugin, {skip: 'private-ip'});
        return true;
    }

    if (ctr) {
        if (ctr.has(plugin, 'skip', /^config\-whitelist/)) {
            plugin.loginfo(connection, 'skipping GL for host whitelisted in config');
            return true;
        }
        if (ctr.has(plugin, 'skip', /^requested/)) {
            plugin.loginfo(connection, 'skipping GL because was asked to previously');
            return true;
        }
    }

    return false;
};

// Is this a "special" sender?
exports.is_sender_special = function(addr) {
    return (!addr.user || addr.user.match(/^(|postmaster|double-bounce(\-?\d{8,12})?)$/));
};

// Was whitelisted previously in this session
exports.was_whitelisted_in_session = function(connection) {
    return connection.transaction.results.has(this, 'pass', 'whitelisted');
};

exports.process_skip_rules = function (connection) {
    var plugin = this;
    var cr = connection.results;

    var skip_cfg = plugin.cfg.skip;
    if (skip_cfg) {
        if (skip_cfg.dnswlorg && cr.has('dnswl.org', 'pass', /^list\.dnswl\.org\([123]\)$/)) {
            return 'dnswl.org(MED)'
        }

        if (skip_cfg.mailspikewl && cr.has('dnswl.org', 'pass', /^wl\.mailspike\.net\((1[7-9]|20)\)$/)) {
            return 'mailspike(H2)'
        }
    }

    return false;
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Build greylist DB key (originally, a "tuple") off supplied params.
// When _to_ is false, we craft +sender+ key
// When _to_ is String, we craft +rcpt+ key
exports.craft_grey_key = function(connection, from, to){
    var plugin = this;

    var key = 'grey:' + plugin.craft_hostid(connection) + ':' + (from || '<>');
    if (to != undefined) {
        key += ':' + (to || '<>');
    }
    return key;
};

// Build white DB key off supplied params.
exports.craft_white_key = function(connection){
    var plugin = this;

    return 'white:' + plugin.craft_hostid(connection);
};

// Return so-called +hostid+.
exports.craft_hostid = function (connection) {
    var plugin = this;
    var trx = connection.transaction;

    if (trx.notes.greylist && trx.notes.greylist.hostid) return trx.notes.greylist.hostid; // "caching"

    var ip = connection.remote_ip;
    var rdns = connection.remote_host;

    var chsit = function(value, reason){  // cache the return value
        if (!value) plugin.logdebug(connection, 'hostid set to IP: ' + reason);

        trx.results.add(plugin, {hostid_type: value ? 'domain' : 'ip', rdns: (value || ip), msg: reason}); // !don't move me.

        value = value || ip;

        return ((trx.notes.greylist = trx.notes.greylist || {}).hostid = value);
    };

    if (!rdns || rdns === 'Unknown' || rdns === 'DNSERROR') // no rDNS . FIXME: use fcrdns results
        return chsit(null, 'no rDNS info for this host');

    rdns = rdns.replace(/\.$/, ''); // strip ending dot, just in case

    var fcrdns = connection.results.get('connect.fcrdns');
    if (!fcrdns) {
        plugin.logwarn(connection, 'No FcrDNS plugin results, fix this.');
        return chsit(null, 'no FcrDNS plugin results');
    }

    if (!connection.results.has('connect.fcrdns', 'pass', 'fcrdns')) // FcrDNS failed
        return chsit(null, 'FcrDNS failed');

    if (connection.results.get('connect.fcrdns').ptr_names.length > 1) // multiple PTR returned
        return chsit(null, 'multiple PTR returned');

    if (connection.results.has('connect.fcrdns', 'fail', /^is_generic/)) // generic/dynamic rDNS record
        return chsit(null, 'rDNS is a generic record');

    if (connection.results.has('connect.fcrdns', 'fail', /^valid_tld/)) // invalid org domain in rDNS
        return chsit(null, 'invalid org domain in rDNS');

    // strip first label up until the tld boundary.
    var decoupled = net_utils.split_hostname(rdns, 3);
    var vardom = decoupled[0]; // "variable" portion of domain
    var dom = decoupled[1]; // "static" portion of domain

    // we check for special cases where rdns looks custom/static, but really is dynamic
    var special_case_info = plugin.check_rdns_for_special_cases(rdns, vardom);
    if (special_case_info) {
        return chsit(null, special_case_info.why);
    }

    var stripped_dom = dom;

    if (vardom) {

        // check for decimal IP in rDNS
        if (vardom.match(String(net_utils.ip_to_long(ip))))
            return chsit(null, 'decimal IP');

        // craft the +hostid+
        var label = vardom.split('.').slice(1).join('.');
        if (label)
            stripped_dom = label + '.' + stripped_dom;
    }

    return chsit(stripped_dom);
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Retrieve _grey_ record
exports.retrieve_grey = function (rcpt_key, sender_key) {
    var plugin = this;
    var multi = plugin.redis.multi();

    multi.hgetall(rcpt_key);
    multi.hgetall(sender_key);

    return Q.ninvoke(multi, 'exec')
            .fail(function (err) {
                plugin.lognotice("DB error: " + util.inspect(err));
                err.what = 'db_error';
                throw err;
            });
};

// Update or create _grey_ record
exports.update_grey = function (key, create) {
    // { created: TS, updated: TS, lifetime: TTL, tried: Integer }

    var plugin = this;
    var multi = plugin.redis.multi();

    var ts_now = Math.round(Date.now() / 1000);

    if (create) {
        var lifetime = plugin.cfg.period.grey;
        var new_record = {created: ts_now, updated: ts_now, lifetime: lifetime, tried: 1};

        multi.hmset(key, new_record);
        multi.expire(key, lifetime);
    } else {
        multi.hincrby(key, 'tried', 1);
        multi.hmset(key, {updated: ts_now});
    }

    return Q.ninvoke(multi, 'exec')
            .then(function(records){
                return create ? new_record : false;
            })
            .fail(function (err) {
                plugin.lognotice("DB error: " + util.inspect(err));
                err.what = 'db_error';
                throw err;
            });
};

// Promote _grey_ record to _white_.
exports.promote_to_white = function (connection, grey_rec) {
    var plugin = this;

    var ts_now = Math.round(Date.now() / 1000);
    var white_ttl = plugin.cfg.period.white;

    // { first_connect: TS, whitelisted: TS, updated: TS, lifetime: TTL, tried: Integer, tried_when_greylisted: Integer }
    var white_rec = {
        first_connect: grey_rec.created,
        whitelisted: ts_now,
        updated: ts_now,
        lifetime: white_ttl,
        tried_when_greylisted: grey_rec.tried,
        tried: 1
    };

    var white_key = plugin.craft_white_key(connection);

    return plugin.db_hmset(white_key, white_rec)
            .then(function () {
                return plugin.db_call('expire', white_key, white_ttl)
                        .then(function () { return white_rec; });
            });
};

// Update _white_ record
exports.update_white_record = function(key, record){
    var plugin = this;

    var multi = plugin.redis.multi();
    var ts_now = Math.round(Date.now() / 1000);

    // { first_connect: TS, whitelisted: TS, updated: TS, lifetime: TTL, tried: Integer, tried_when_greylisted: Integer }
    multi.hincrby(key, 'tried', 1);
    multi.hmset(key, {updated: ts_now});
    multi.expire(key, record.lifetime);

    return Q.ninvoke(multi, 'exec')
            .then(function(){ return record })
            .fail(function (err) {
                plugin.lognotice("DB error: " + util.inspect(err));
                err.what = 'db_error';
                throw err;
            });
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// @return [promise]        resulting DB data or a failure
exports.db_lookup = function(key){
    return this.db_call('HGETALL', key)
        .then(function(result){
            if (result && typeof result === 'object') { // groom known-to-be numeric values
                ['created', 'updated', 'lifetime', 'tried', 'first_connect', 'whitelisted', 'tried_when_greylisted'].forEach(function(kk){
                    var val = result[kk];
                    if (val !== undefined) {
                        result[kk] = Number(val);
                    }
                })
            }
            return result;
        });
};

// @param what              Object with {field: val}
// @return [promise]        resulting DB data or a failure
exports.db_hmset = function(key, what) {
    return this.db_call('HMSET', key, what);
};

// @return [promise]
exports.db_incrby = function(key, field, value) {
    return this.db_call('HINCRBY', key, field, value);
};

exports.db_call = function(op, key, args) {
    var plugin = this;

    var meth_args = [key];
    if (args) {
        meth_args.push(args);
    }
    plugin.logdebug('(redis) ', [op, meth_args].join(', '));

    return Q.npost(plugin.redis, op, meth_args)
            .fail(function (err) {
                err.what = 'db_error';
                throw err;
            });
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
exports.addr_in_list = function (type, address) {
    var plugin = this;

    if (!plugin.whitelist[type]) {
        plugin.logwarn("List not defined: " + type);
        return false;
    }

    if (plugin.whitelist[type][address]) { return true; }

    try {
        var addr = new Address(address);
        return !!plugin.whitelist[type][addr.host];
    } catch (err) {
        return false;
    }
};

exports.ip_in_list = function(ip){
    var plugin = this;
    var ipobj = ipaddr.parse(ip);

    try {
        var list = plugin.whitelist.ip;

        for (var i = 0; i < list.length; i++) {
            if (ipobj.match(list[i]))
                return true;
        }
    } catch (e) {
        plugin.logwarn('some error: ' + e.message + ' bt: ' + e.stack);
    }

    return false;
};

// Match patterns in the list against (end of) domain
exports.domain_in_list = function(list_name, domain) {
    var plugin = this;
    var list = plugin.list[list_name];

    if (!list) {
        plugin.logwarn("List not defined: " + list_name);
        return false;
    }

    for (var i = 0; i < list.length; i++) {
        if (domain.length - domain.lastIndexOf(list[i]) == list[i].length)
            return true;
    }

    return false;
};

// Check for special rDNS cases
// @return {type: 'dynamic'} if rnds is dynamic (hostid should be IP)
exports.check_rdns_for_special_cases = function (domain, label) {
    var plugin = this;

    // ptr for these is in fact dynamic
    if (plugin.domain_in_list('dyndom', domain))
        return {type: 'dynamic', why: 'rDNS considered dynamic: listed in dynamic.domains config list'};

    return false;
};
