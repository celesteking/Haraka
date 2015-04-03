'use strict';
// log to Elasticsearch

exports.register = function() {
    var plugin = this;

    var elasticsearch;
    try {
        elasticsearch = require('elasticsearch');
    }
    catch (err) {
        plugin.logerror(err);
        return;
    }

    plugin.cfg = plugin.config.get('log.elasticsearch.ini');

    if (!plugin.cfg.main.host) {
        plugin.cfg.main.host = 'localhost';
    }
    if (!plugin.cfg.main.port) {
        plugin.cfg.main.port = '9200';
    }

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
            plugin.logerror('Elasticsearch cluster is down!');
        } else {
            plugin.lognotice('Elasticsearch is connected');
        }
    });

    plugin.register_hook('disconnect', 'elasticsearch');
};

exports.hook_reset_transaction = function (next, connection) {
    var plugin = this;

    var rcpts = [];
    connection.transaction.rcpt_to.forEach(function (r) {
        rcpts.push(r.original);
    });

    connection.results.push(plugin, { txn: {
            mail_from: connection.transaction.mail_from.original,
            rcpt_to: rcpts,
        }
    });

    next();
};

exports.elasticsearch = function (next, connection) {
    var plugin = this;

    // note that we make a copy of the result store, so subsequent changes
    // here don't alter the original (by reference)
    var res = {
        timestamp: new Date().toISOString(),
        pi:   JSON.parse(JSON.stringify(connection.results.get_all())),
        txn:  [],
    };

    if (res.pi['log.elasticsearch']) {
        res.txn = res.pi['log.elasticsearch'].txn;
        delete res.pi['log.elasticsearch'];
    }

    // TODO: use a naming convention to hide "plugin only" data

    for (var p in res.pi) {
        if (res.pi[p].human) { delete res.pi[p].human; }
        if (res.pi[p].human_html) { delete res.pi[p].human_html; }

        var trimmed = exports.trimPluginName(p);
        if (trimmed !== p) {
            res.pi[trimmed] = res.pi[p];
            delete res.pi[p];
            p = trimmed;
        }

        plugin.prune_empty(res.pi[p]);

        switch (p) {
            case 'karma':
                delete res.pi.karma.todo;
                delete res.pi.karma.pass;
                delete res.pi.karma.skip;
                break;
            case 'access':
                delete res.pi.access.pass;
                break;
            case 'uribl':
                delete res.pi.uribl.skip;
                delete res.pi.uribl.pass;
                break;
            case 'dnsbl':
                delete res.pi.dnsbl.pass;
                break;
            case 'fcrdns':
                var arr = plugin.objToArray(res.pi.fcrdns.ptr_name_to_ip);
                res.pi.fcrdns.ptr_name_to_ip = arr;
                break;
            case 'max_unrecognized_commands':
                res.unrecognized_commands =
                    res.pi.max_unrecognized_commands.count;
                delete res.pi.max_unrecognized_commands;
                break;
        }
    }

    plugin.populate_conn_properties(connection, res);

    // c.lognotice(plugin, JSON.stringify(res));
    plugin.save_to_elasticsearch(connection, res);

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

exports.trimPluginName = function (name) {

    var parts = name.split('.');

    switch (parts[0]) {
        case 'helo':  
            return 'helo';
        case 'connect':
        case 'mail_from':
        case 'rcpt_to':
        case 'data':
        case 'queue':
            return parts.slice(1).join('.');
    }
    return name;
};

exports.save_to_elasticsearch = function (conn, res) {
    var plugin = this;

    try {
        plugin.es.create({
            index: exports.getIndexName(),
            type: 'haraka',
            id: conn.uuid,
            body: JSON.stringify(res),
        }, function (error, response) {
            if (error) {
                conn.logerror(plugin, error);
                return;
            }
            // c.lognotice(plugin, response);
            // ...
        });
    }
    catch (e) {
        conn.logerror(plugin, e);
    }
};

exports.getIndexName = function () {

    var name = 'smtp-connection-';
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
     'remote_ip', 'remote_host', 'remote_port', 'remote_info',
     'greeting', 'hello_host',
     'relaying', 'esmtp', 'using_tls'
    ].forEach(function (f) {
        if (conn[f] === undefined) { return; }
        res[f] = conn[f];
    });

    res.bytes    = conn.total_bytes;
    res.duration = (Date.now() - conn.start_time)/1000;
    res.rcpts    = conn.rcpt_count;
    res.msgs     = conn.msg_count;
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

exports.get_results = function (connection, pi_name) {
    var plugin = this;

    /*
    // calling code for this no-longer-used function
    plugin.plugins = plugin.config.get('plugins', 'list');
    plugin.plugins.forEach(function (p) {
        var r = plugin.get_results(connection, p);
        if (r === undefined) { return; }
        if (Object.keys(r).length === 0) { return; }
    });
    /*/

    var raw = {
        cxn: connection.results.get(pi_name),
    };
    if (connection.transaction) {
        raw.txn = connection.transaction.results.get(pi_name);
    }
    if (!raw.cxn && !raw.txn) return;

    var merged = {};

    // merge results
    Object.keys(raw).forEach(function (loc) {
        // connection.logerror(plugin, "loc " + loc);
        if (!raw[loc]) { return; }
        for (var key in raw[loc]) {
            if (/human/.test(key)) { continue; }
            if (key === 'todo' && pi_name === 'karma') { continue; }
            // connection.logerror(plugin, "key " + key);
            var val = raw[loc][key];
            // connection.logerror(plugin, "key " + key);
            
        }
    });

    return merged;
};

