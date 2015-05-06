'use strict';
// log to Elasticsearch

var utils = require('./utils');

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
        host: plugin.cfg.main.host + ':' + plugin.cfg.main.port,
        // log: 'trace',
    });

    plugin.es.ping({
        // ping usually has a 100ms timeout
        requestTimeout: 1000,

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
    });

    plugin.register_hook('reset_transaction', 'log_transaction');
    plugin.register_hook('disconnect',        'log_connection');
};

exports.load_es_ini = function () {
    var plugin = this;

    plugin.cfg = plugin.config.get('log.elasticsearch.ini', function () {
        plugin.load_es_ini();
    });

    if (!plugin.cfg.main.host) {
        plugin.cfg.main.host = 'localhost';
    }
    if (!plugin.cfg.main.port) {
        plugin.cfg.main.port = '9200';
    }
};

exports.log_transaction = function (next, connection) {
    var plugin = this;

    if (plugin.cfg.ignore_hosts) {
        if (plugin.cfg.ignore_hosts[connection.remote_host]) return next();
    }

    var res = plugin.get_plugin_results(connection);
    res.timestamp = new Date().toISOString();
    res.txn = {
        mail_from: connection.transaction.mail_from.original,
        rcpts: [],
        rcpt_count: connection.transaction.rcpt_count,
        header: {},
    };

    connection.transaction.rcpt_to.forEach(function (r) {
        res.txn.rcpts.push(r.original);
    });

    ['From', 'To', 'Subject'].forEach(function (h) {
        var r = connection.transaction.header.get_decoded(h);
        if (!r) return;
        res.txn.header[h] = r;
    });

    plugin.populate_conn_properties(connection, res);
    plugin.es.create({
        index: exports.getIndexName('transaction'),
        type: 'haraka',
        id: connection.transaction.uuid,
        body: JSON.stringify(res),
    }, function (error, response) {
        if (error) {
            connection.logerror(plugin, error.message);
            return next();
        }
        // connection.loginfo(plugin, response);
        connection.notes.elasticsearch=connection.tran_count;
        next();
    });
};

exports.log_connection = function (next, connection) {
    var plugin = this;

    if (connection.notes.elasticsearch &&
        connection.notes.elasticsearch === connection.tran_count) {
        connection.logdebug(plugin, 'skipping already logged txn');
        return next();
    }

    var res = plugin.get_plugin_results(connection);
    res.timestamp = new Date().toISOString();

    plugin.populate_conn_properties(connection, res);

    // connection.lognotice(plugin, JSON.stringify(res));
    plugin.es.create({
        index: exports.getIndexName('connection'),
        type: 'haraka',
        id: connection.uuid,
        body: JSON.stringify(res),
    }, function (error, response) {
        if (error) {
            connection.logerror(plugin, error.message);
            return;
        }
        // connection.loginfo(plugin, response);
    });

    next();
};

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

exports.populate_conn_properties = function (conn, res) {

    ['local_ip', 'local_port',
     'remote_ip', 'remote_host', 'remote_port',
     'greeting', 'hello_host',
     'relaying', 'esmtp', 'using_tls', 'errors',
     'rcpt_count', 'msg_count', 'total_bytes'
    ].forEach(function (f) {
        if (conn[f] === undefined) { return; }
        if (conn[f] === 0) { return; }
        res[f] = conn[f];
    });

    res.duration = (Date.now() - conn.start_time)/1000;
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
        plugin.prune_zero(pir, name);
    }

    if (connection.transaction) {
        var txr = JSON.parse(JSON.stringify(
                    connection.transaction.results.get_all()));

        for (name in txr) {
            plugin.trim_plugin_names(txr, name);
        }
        for (name in txr) {
            plugin.prune_noisy(txr, name);
            plugin.prune_empty(txr[name]);
            plugin.prune_zero(txr, name);
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

exports.trimPluginName = function (name) {

    // for plugins named like: data.headers or connect.geoip, strip off the
    // phase prefix and return `headers` or `geoip`
    var parts = name.split('.');

    switch (parts[0]) {
        case 'helo':
            return 'helo';
        case 'connect':
        case 'mail_from':
        case 'rcpt_to':
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
            delete res.karma.pass;
            delete res.karma.skip;
            break;
        case 'access':
            delete res.access.pass;
            break;
        case 'uribl':
            delete res.uribl.skip;
            delete res.uribl.pass;
            break;
        case 'dnsbl':
            delete res.dnsbl.pass;
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
            delete res.line0;
            delete res.hits;
            if (res.headers) {
                delete res.headers.Tests;
                delete res.headers.Level;
            }
    }
};

exports.prune_zero = function (res, name) {
    for (var e in res[name]) {
        if (res[name][e] !== 0) continue;
        delete res[name][e];
    }
};
