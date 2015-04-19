



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
