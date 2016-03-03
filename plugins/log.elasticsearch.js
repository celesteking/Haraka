'use strict';

// V: 0.2

// log to Elasticsearch

var utils = require('Haraka/utils');
var util = require('util');

exports.register = function() {
    var plugin = this;

    try {
        var elasticsearch = require('elasticsearch');
    }
    catch (err) {
        plugin.logerror(err);
        return;
    }

    plugin.load_es_ini();

    plugin.es = new elasticsearch.Client({
        host: plugin.cfg.main.host + ':' + plugin.cfg.main.port
        // log: 'trace',
    });

    plugin.es.ping({
        // ping usually has a 100ms timeout
        requestTimeout: plugin.cfg.timeout || 1000,

        // undocumented params are appended to the query string
        hello: "elasticsearch!"
        }, function (error) {
            if (error) {
                // we don't bother error handling hear b/c the ES library does
                // that for us.
                plugin.logerror('cluster is down!');
            }
            else {
                plugin.lognotice('connected');
            }
        }
    );

    plugin.register_hook('reset_transaction',   'log_transaction');
    plugin.register_hook('disconnect',          'log_connection');
    plugin.register_hook('delivered',           'log_delivered');
    plugin.register_hook('deferred',            'log_deferred');
    plugin.register_hook('bounce',              'log_bounced');

    if (plugin.cfg.main.log_events) {
        plugin.register_hook('log',             'log_hooked');
    }
};

exports.load_es_ini = function () {
    var plugin = this;

    plugin.cfg = plugin.config.get('log.elasticsearch.ini', 'ini', function () {
        plugin.load_es_ini();
    }, {booleans: [
        '+clean.karma', '+clean.access', '+clean.uribl', '+clean.dnsbl', '+clean.fcrdns', '+clean.spamassassin',
        '-log_events'
    ]});

    if (!plugin.cfg.main.host) {
        plugin.cfg.main.host = 'localhost';
    }
    if (!plugin.cfg.main.port) {
        plugin.cfg.main.port = '9200';
    }
};

exports.log_transaction = function (next, connection) {
    var plugin = this;
    var trans = connection.transaction;

    if (plugin.cfg.ignore_hosts) {
        if (plugin.cfg.ignore_hosts[connection.remote_host]) return next();
    }

    var res = { plugins: plugin.get_plugin_results(connection) };

    res.timestamp = new Date().toISOString();

    res.txn = {
        uuid: trans.uuid,
        mail_from: trans.mail_from.address(),
        rcpts: [],
        rcpt_count: trans.rcpt_count,
        header: {},
        message_size: trans.data_bytes,
        message_status: trans.msg_status
    };

    trans.rcpt_to.forEach(function (r) {
        res.txn.rcpts.push(r.address());
    });

    var rcpt_to_info = trans.results.get('rcpt_to.info');
    if (rcpt_to_info && rcpt_to_info.recipients && rcpt_to_info.recipients.length > 0) {
        res.txn['rcpts_provided'] = rcpt_to_info.recipients;
        // FIXME: count smtp_forward'ed recipients in!
        res.txn['rcpts_rejected'] = rcpt_to_info.recipients.filter(function(e){ return res.txn.rcpts.indexOf(e) == -1 });
    }

    if (trans.notes.th_table && Object.keys(trans.notes.th_table).length > 0) {
        res.txn['terminator'] = trans.notes.th_table;

        var smtp_fwd_notes = connection.transaction.notes.smtp_forward;

        if (smtp_fwd_notes && smtp_fwd_notes.recipients) { // store smtp_forward RCPT data
            res.txn['rcpts_forwarded'] = smtp_fwd_notes.recipients;
        }
    }

    if (connection.relaying || (smtp_fwd_notes && smtp_fwd_notes.rcpt_count && smtp_fwd_notes.rcpt_count.outbound > 0)) {
        // create outbound object by default for transactions that will require it
        res['outbound'] = {
            log: [],
            rcpt_status: {},
            status: {
                state: (trans.msg_status.tempfailed || trans.msg_status.rejected) ? 'completed' : 'progress',
                rcpt: {
                    count: (smtp_fwd_notes && smtp_fwd_notes.rcpt_count) ? smtp_fwd_notes.rcpt_count.outbound : trans.rcpt_count.accept,
                    delivered: 0,
                    rejected: 0,
                    deferred: 0
                }
            }
        };
    }


    ['From', 'To', 'Subject', 'Message-Id'].forEach(function (h) {
        var r = trans.header.get_decoded(h);
        if (r) res.txn.header[h] = r;
    });

    plugin.populate_conn_properties(connection, res);

    var jsonized = JSON.stringify(res, null, 4);
//    plugin.lognotice(jsonized);
//    plugin.logwarn(util.inspect(connection, {color: true, depth: 6}));

    plugin.create_es_document({
        index: exports.getIndexName('transaction'),
        id: trans.uuid,
        document: jsonized
    });

    // hook reset_transaction doesn't seem to wait for next(). If I
    // wait until after I get a response back from ES, Haraka throws
    // "Error: We are already running hooks!". So we record that we've sent
    // to ES (so connection isn't saved too) and hope for the best.
    connection.notes.elasticsearch=connection.tran_count;
    next();
};

exports.log_connection = function (next, connection) {
    var plugin = this;

    if (plugin.cfg.ignore_hosts) {
        if (plugin.cfg.ignore_hosts[connection.remote_host]) return next();
    }

    if (connection.notes.elasticsearch &&
        connection.notes.elasticsearch === connection.tran_count) {
        connection.logdebug(plugin, 'skipping already logged txn');
        return next();
    }

    var res = { "plugins": plugin.get_plugin_results(connection) };
    res.timestamp = new Date().toISOString();

    plugin.populate_conn_properties(connection, res);

//    connection.lognotice(plugin, JSON.stringify(res, null, 4));

    plugin.create_es_document({
        index: exports.getIndexName('connection'),
        id: connection.uuid,
        document: JSON.stringify(res)
    });

    next();
};

// status: [host 0, ip 1, response 2, delay 3, port 4, mode 5, ok_recips 6, secured 7, authenticated 8]
exports.log_delivered = function(next, hmail, status) {
    var plugin = this;

    plugin.logdebug("DELIVERED: ip=" + status[1] + ' rcpts=' + status[6].map(function(e){ return e.address() }));
    if (!hmail.todo.notes.th_table)
        plugin.logwarn("DELIVERED: It looks like a LOCAL bounce");
//    plugin.lognotice("HMAIL: " + util.inspect(hmail, {depth: 6}));

    var txn_uuid = hmail.todo.notes.txn_uuid;
    if (!txn_uuid) {
        plugin.logwarn(hmail, "Can't update orphan: " + util.inspect(hmail).replace(/\n/g, ' '));
        return next();
    }

    var new_events = [];
    var rcpt_status = {};
    var date_now = new Date().toISOString();

    if (hmail.todo.notes.bounce_origin == 'ours' && hmail.todo.notes.bounced_addrs.length > 0) { // bounce delivery notification

        hmail.todo.notes.bounced_addrs.forEach(function(addr) {
            addr = addr || '<>';

            new_events.push(date_now + ': ' + addr + ': Bounce delivered: ' + status[2]);
            rcpt_status[addr] = {bounce_delivery: 'completed', bounce_delivery_time: date_now };
        });

    } else {  // regular delivery notification

        status[6].forEach(function(e) {
            var addr =  (e.address() || '<>');

            new_events.push(date_now + ': ' + addr + ': ' + status[2]);

            var rstatus = {state: 'delivered', message: status[2], time: date_now, ip: status[1] };
            if (status.bind_ip) { rstatus.bind_ip = status.bind_ip }

            rcpt_status[addr] = rstatus;
        });
    }

    var es_opts = {
        uuid: txn_uuid,
        // some defaults
        rcpt_count: hmail.todo.rcpt_to.length,
        rcpt_delivered_count: status[6].length,
        //
        rcpt_status: rcpt_status,
        new_events: new_events
    };

    exports.update_es_txn_document(es_opts);

    return next();
};

// {delay: delay, err: err}
exports.log_deferred = function(next, hmail, opts){
    var plugin = this;

    var error_message = opts.err;
    var error = opts.extra;

    plugin.logdebug("Deferred: " + error_message + ', extra: ' + util.inspect(error));
//    plugin.lognotice("Deferred hmail rcpt: " + util.inspect(hmail.todo.rcpt_to.map(function(e){ return e.original })));

    if (!hmail.todo.notes.th_table)
        plugin.logwarn("Deferred: It looks like a LOCAL bounce");

    var deferred_addrs = (error && error.rcpt) || hmail.todo.rcpt_to;

    var txn_uuid = hmail.todo.notes.txn_uuid;
    if (!txn_uuid) {
        plugin.logwarn(hmail, "Can't update orphan: " + util.inspect(hmail).replace(/\n/g, ' '));
        return next();
    }

    var new_events = [];
    var rcpt_status = {};
    var date_now = new Date().toISOString();

    deferred_addrs.forEach(function(rcpt) {
        var addr =  rcpt.address();
        var bounce_message = rcpt.reason || error_message || 'Unknown deferral reason';

        new_events.push(date_now + ': ' + addr + ': ' + bounce_message);
        rcpt_status[addr] = { state: 'deferred', message: bounce_message, time: date_now };
    });

    var es_opts = {
        uuid: txn_uuid,
        // some defaults
        rcpt_count: deferred_addrs.length,
        rcpt_deferred_count: deferred_addrs.length,
        //
        rcpt_status: rcpt_status,
        new_events: new_events
    };

    exports.update_es_txn_document(es_opts);

    return next();
};


exports.log_bounced = function(next, hmail, error){
    var plugin = this;

    plugin.logdebug("Bounced: " + util.inspect(error));

    var bounced_addrs = error.bounced_rcpt || hmail.todo.rcpt_to;

    var txn_uuid = hmail.todo.notes.txn_uuid;
    if (!txn_uuid) {
        plugin.logwarn(hmail, "Can't update orphan: " + util.inspect(hmail).replace(/\n/g, ' '));
        return next();
    }

    var new_events = [];
    var rcpt_status = {};
    var date_now = new Date().toISOString();

    bounced_addrs.forEach(function(rcpt) {
        var addr =  rcpt.address();
        var bounce_message = rcpt.reason || error.message || 'Unknown rejection reason';

        new_events.push(date_now + ': ' + addr + ': ' + bounce_message);
        rcpt_status[addr] = { state: 'rejected', message: bounce_message, time: date_now, bounce_delivery: 'progress' };
    });

    var es_opts = {
        uuid: txn_uuid,
        // some defaults
        rcpt_count: bounced_addrs.length,
        rcpt_rejected_count: bounced_addrs.length,
        //
        rcpt_status: rcpt_status,
        new_events: new_events
    };

    exports.update_es_txn_document(es_opts);

    return next(CONT, { notes: {
        txn_uuid: txn_uuid,
        bounce_origin: 'ours',
        bounced_addrs: bounced_addrs.map(function(e){ return e.address() || '<>' })
    }});
};

// ---------------------------------------------------------------------------

exports.update_es_txn_document = function(opts){
    var es_opts = {
        id: opts.uuid,
        index: exports.getIndexName('transaction'),
        document: {
            script_file: 'haraka-update-trans-outbound',
            params: {
                new_events: opts.new_events,
                rcpt_status: opts.rcpt_status
            },
            upsert: {
                txn: {
                    type: "outbound-orphan",
                    rcpt_count: {
                        given: opts.rcpt_count || 0
                    }
                },
                outbound: {
                    log: opts.new_events || [],
                    rcpt_status: opts.rcpt_status || {},
                    status: {
                        state: 'completed',
                        rcpt: {
                            count: opts.rcpt_count,
                            delivered: opts.rcpt_delivered_count || 0,
                            rejected: opts.rcpt_rejected_count || 0,
                            deferred: opts.rcpt_deferred_count || 0
                        }
                    }
                }
            }
        }
    };

    return exports.update_es_document(es_opts);
};

exports.update_es_document = function(opts){
    var plugin = this;

    plugin.logdebug("updating idx=" + opts.index + ' id=' + opts.id + ' doc=' + util.inspect(opts.document, {depth: 5}).replace(/\n/g, ' '));

    plugin.es.update({
        index: opts.index,
        type: 'haraka',
        id: opts.id,
        body: opts.document,
        retryOnConflict: 30
    }, function (error, response) {
        if (error) plugin.logerror(error.message);
        // connection.loginfo(plugin, response);
    });
};

exports.create_es_document = function(opts){

    return this.es.create({
        index: opts.index,
        type: 'haraka',
        id: opts.id,
        body: opts.document
    }, function (error, response) {
        if (error) {
            util.error("ES: " + error.message);
        }
        // connection.loginfo(plugin, response);
    });
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Log an event to ES smtp-error index
// params:
//  uuid
//  level   (protocol|debug|info|warn|error|notice|crit)
//  origin
//  plugin,conn,txn
//  msg
exports.log_event = function(params){
    var myself = this;

    var docu = {
        level: params.level || 'debug',
        uuid: params.uuid || (params.txn && params.txn.uuid) || (params.conn || params.conn.uuid) || '-',
        origin: params.origin || (params.plugin && params.plugin.name) || 'core',
        message: params.msg,
        timestamp: new Date().toISOString()
    };

    var es_opts = {
        index: exports.getIndexName('events'),
        id: null,
        document: docu
    };

    return myself.create_es_document(es_opts);
};

exports.log_hooked = function(next, logger, log){
    if (log.obj && log.obj.origin != this.name)
        this.log_event({level: log.obj.level, uuid: log.obj.uuid, origin: log.obj.origin, msg: log.obj.msg});
    return next();
};
// ---------------------------------------------------------------------------

exports.objToArray = function (obj) {
    var arr = [];
    if (!obj || typeof obj !== 'object') { return arr; }
    Object.keys(obj).forEach(function (k) {
        arr.push({ k: k, v: obj[k] });
    });
    return arr;
};

exports.getIndexName = function (section) {

    // Elasticsearch indexes named like: smtp-connection-2015-05-05
    //                                   smtp-transaction-2015-05-05
    var name = 'smtp-' + section + '-';
    var date = new Date();
    var d = date.getDate();
    var m = date.getMonth() + 1;
    return name +
           date.getFullYear() +
           '-' + (m<=9 ? '0' + m : m) +
           '-' + (d <= 9 ? '0' + d : d);
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
exports.populate_conn_properties = function (conn, res) {

    ['local_ip', 'local_port',
        'remote_ip', 'remote_host', 'remote_port',
        'greeting', 'hello_host',
        'relaying', 'esmtp', 'using_tls', 'errors', 'pipelining',
        'msg_count', 'total_bytes',
        'notes.tls', 'early',
        'uuid'
    ].forEach(function (f) {
        if (conn[f] === undefined) {
            return;
        }
        res[f] = conn[f];
    });

    res.duration = (Date.now() - conn.start_time)/1000;

    res.last_response = String(conn.last_response).trim();
    res.last_reject = String(conn.last_reject).trim();
};

exports.get_plugin_results = function (connection) {
    var plugin = this;

    var name;
    // note that we make a copy of the result store, so subsequent changes
    // here don't alter the original (by reference)
    var pir = JSON.parse(JSON.stringify(connection.results.get_all()));
    for (name in pir) {
        plugin.trim_plugin_names(pir, name);
    }
    for (name in pir) {
        plugin.prune_noisy(pir, name);
        plugin.prune_empty(pir[name]);
//        plugin.prune_zero(pir, name);
        plugin.prune_redundant_cxn(pir, name);
        plugin.process_connection_results(pir, name);
    }

    if (connection.transaction) {
        try {
            var txr = JSON.parse(JSON.stringify(
                        connection.transaction.results.get_all()));
        }
        catch (e) {
            connection.transaction.results.add(plugin, {err: e.message });
            return pir;
        }

        for (name in txr) {
            plugin.trim_plugin_names(txr, name);
        }
        for (name in txr) {
            plugin.prune_noisy(txr, name);
            plugin.prune_empty(txr[name]);
//            plugin.prune_zero(txr, name);
            plugin.prune_redundant_txn(txr, name);
            plugin.process_transaction_results(pir, txr, name);
        }

        // merge transaction results into connection results
        for (name in txr) {
            if (!pir[name]) {
                pir[name] = txr[name];
                delete txr[name];
            }
            else {
                utils.extend(pir[name], txr[name]);
            }
        }
    }

    return pir;
};

// in-place beautification
exports.beautify_plugin_name = function(name) {
    switch (name) {
        case 'auth/auth_anti_brute':
            return 'auth_anti_brute';
        case 'auth/auth_fred':
            return 'auth_fred';
    }
    return name;
};

exports.trimPluginName = function (name) {
    // beautify plugin name first
    name = this.beautify_plugin_name(name);

    // for plugins named like: data.headers or connect.geoip, strip off the
    // phase prefix and return `headers` or `geoip`
    var parts = name.split('.');

    if (parts.length == 1)
        return name;

    switch (parts[0]) {
        case 'helo':
            return 'helo';
        case 'connect':
        case 'mail_from':
//        case 'rcpt_to':
        case 'data':
            return parts.slice(1).join('.');
    }

    return name;
};

exports.trim_plugin_names = function (res, name) {
    var trimmed = exports.trimPluginName(name);
    if (trimmed === name) return;

    res[trimmed] = res[name];
    delete res[name];
    name = trimmed;
};

exports.prune_empty = function (pi) {

    // remove undefined keys and empty strings, arrays, or objects
    for (var e in pi) {
        var val = pi[e];
        if (val === undefined) {
            delete pi[e];
            continue;
        }

        if (typeof val === 'string') {
            if (val === '') {
               delete pi[e];
               continue;
            }
        }
        else if (Array.isArray(val)) {
            if (val.length === 0) {
                delete pi[e];
                continue;
            }
        }
        else if (typeof val === 'object') {
            if (Object.keys(val).length === 0) {
                delete pi[e];
                continue;
            }
        }
    }
};

exports.prune_noisy = function (res, pi) {
    var plugin = this;

    if (res[pi].human) { delete res[pi].human; }
    if (res[pi].human_html) { delete res[pi].human_html; }
    if (res[pi]._watch_saw) { delete res[pi]._watch_saw; }

    switch (pi) {
        case 'karma':
            delete res.karma.todo;
            if (plugin.cfg.clean.karma) {
                delete res.karma.pass;
                delete res.karma.skip;
            }
            break;
        case 'access':
            if (plugin.cfg.clean.access) {
                delete res.access.pass;
            }
            break;
        case 'uribl':
            if (plugin.cfg.clean.uribl) {
                delete res.uribl.skip;
                delete res.uribl.pass;
            }
            break;
        case 'dnsbl':
            if (plugin.cfg.clean.dnsbl) {
                delete res.dnsbl.pass;
            }
            break;
        case 'fcrdns':
            var arr = plugin.objToArray(res.fcrdns.ptr_name_to_ip);
            res.fcrdns.ptr_name_to_ip = arr;
            break;
        case 'max_unrecognized_commands':
            res.unrecognized_commands =
                res.max_unrecognized_commands.count;
            delete res.max_unrecognized_commands;
            break;
        case 'spamassassin':
            if (plugin.cfg.clean.spamassassin) {
                delete res.spamassassin.line0;
                if (res.spamassassin.headers) {
                    delete res.spamassassin.headers.Tests;
                    delete res.spamassassin.headers.Level;
                }
            }
            break;
        case 'rcpt_to.info':
            break;
    }
};

exports.prune_zero = function (res, name) {
    for (var e in res[name]) {
        if (res[name][e] !== 0) continue;
        delete res[name][e];
    }
};

exports.prune_redundant_cxn = function (res, name) {
    switch (name) {
        case 'helo':
            if (res.helo && res.helo.helo_host) {
                delete res.helo.helo_host;
            }
            break;
        case 'p0f':
            if (res.p0f && res.p0f.query) {
                delete res.p0f.query;
            }
            break;
    }
};

exports.prune_redundant_txn = function (res, name) {
    switch (name) {
        case 'spamassassin':
            if (!res.spamassassin) break;
            delete res.spamassassin.hits;
            if (res.spamassassin.headers) {
                if (res.spamassassin.headers.Flag) {
                    delete res.spamassassin.headers.Flag;
                }
            }
            break;
        case 'spf':
            if (!res.spf) break;

    }
};

// Do something with connection results obj
exports.process_connection_results = function(pir, name) {
    switch (name) {
        case 'spf':
            delete pir.spf.scope;  // we already know the scope
            pir.spf = { helo: pir.spf };
            break;
    }
};

// Do something with transaction results obj
exports.process_transaction_results = function(pir, txr, name) {
    switch (name) {
        case 'spf':
            delete txr.spf.scope; // we already know the scope
            pir['spf'] = pir['spf'] || {}; // work around missing connection.spf result
            pir['spf']['mfrom'] = txr.spf;
            delete txr.spf;
            break;
    }
};
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
