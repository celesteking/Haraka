# log.elasticsearch

# Logging

Logs nothing by default. 

# Errors

The elasticsearch module has very robust error handling built in. If there's a
connection issue, an error such as these will be emitted when Haraka starts
up:

* Elasticsearch cluster is down!
* No Living connections

However, ES will continue attempting to connect and when the ES server becomes
available, logging will begin. If errors are encountered trying to save data
to ES, they look like this:

* No Living connections
* Request Timeout after 30000ms

They normally fix themselves when ES resumes working properly.


# Index map template

```json
curl -XPUT localhost:9200/_template/haraka_results -d '
{
    "template" : "smtp-*",
    "mappings" : {
        "haraka" : {
            "dynamic_templates" : [
                { "string_fields" : {
                       "match" : "fail",
                       "match_mapping_type" : "string",
                       "mapping" : {
                         "type" : "string", "index" : "not_analyzed"
                       }
                    }
                },
                { "string_fields" : {
                       "match" : "pass",
                       "match_mapping_type" : "string",
                       "mapping" : {
                         "type" : "string", "index" : "not_analyzed"
                       }
                    }
                },
                { "string_fields" : {
                       "match" : "skip",
                       "match_mapping_type" : "string",
                       "mapping" : {
                         "type" : "string", "index" : "not_analyzed"
                       }
                    }
                },
                { "string_fields" : {
                       "match" : "msg",
                       "match_mapping_type" : "string",
                       "mapping" : {
                         "type" : "string", "index" : "not_analyzed"
                       }
                    }
                },
                { "string_fields" : {
                       "match" : "err",
                       "match_mapping_type" : "string",
                       "mapping" : {
                         "type" : "string", "index" : "not_analyzed"
                       }
                    }
                }
            ],
            "properties" : {
                "hello_host" : { "type" : "string", "index" : "not_analyzed" }, 
                "remote_host" : { "type" : "string", "index" : "not_analyzed" },
                "local_ip" : { "type" : "ip" },
                "remote_ip" : { "type" : "ip" },
                "asn" : {
                    "properties" : {
                        "org" : { "type" : "string", "index" : "not_analyzed" }
                    }
                },
                "geoip" : {
                    "properties" : {
                        "org" : { "type" : "string", "index" : "not_analyzed" }
                    }
                },
                "helo" : {
                    "properties" : {
                        "ips" : { "type" : "string", "index" : "not_analyzed" }
                    }
                },
                "fcrdns" : {
                    "properties" : {
                        "fcrdns" : { "type" : "string", "index" : "not_analyzed" },
                        "other_ips" : { "type" : "string", "index" : "not_analyzed" },
                        "ptr_names" : { "type" : "string", "index" : "not_analyzed" }
                    }
                },
                "p0f" : {
                    "properties" : {
                        "os_flavor" : { "type" : "string", "index" : "not_analyzed" }
                    }
                },
                "rspamd" : {
                    "properties" : {
                        "emails" : { "type" : "string", "index" : "not_analyzed" },
                        "urls" : { "type" : "string", "index" : "not_analyzed" },
                        "messages" : { "type" : "string", "index" : "not_analyzed" }
                    }
                },
                "karma" : {
                    "properties" : {
                        "connect" : { "type" : "double" },
                        "history" : { "type" : "double" },
                        "total_connects" : { "type" : "double" },
                        "neighbors" : { "type" : "double" }
                    }
                },
                "spamassassin" : {
                    "properties" : {
                        "headers": {
                            "properties": {
                                "report" : { "type" : "string", "index" : "not_analyzed" },
                                "Status" : { "type" : "string", "index" : "not_analyzed" }
                            }
                        },
                        "line0" : { "type" : "string", "index" : "not_analyzed" },
                        "reqd"  : { "type" : "double" },
                        "score" : { "type" : "double" },
                        "tests" : { "type" : "string", "index" : "not_analyzed" }
                    }
                },
                "spf" : {
                    "properties" : {
                        "domain" : { "type" : "string", "index" : "not_analyzed" }
                    }
                },
                "txn" : {
                    "properties" : {
                        "header": {
                            "properties": {
                                "From" : { "type" : "string", "index" : "not_analyzed" },
                                "Subject" : { "type" : "string", "index" : "not_analyzed" },
                                "To" : { "type" : "string", "index" : "not_analyzed" }
                            }
                        },
                        "mail_from" : { "type" : "string", "index" : "not_analyzed" },
                        "rcpts" : { "type" : "string", "index" : "not_analyzed" }
                    }
                }
            }
        }
    }
}'

```
