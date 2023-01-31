# Roadmap

The following is a list of plugins and features that we plan to add to vSMTP. (It is a ___Work in progress___)

## Filters and security components

| Name | License | Comment | Type | Status |
| :--- | :--- | :--- | :--- | :--- |
| N/A | Public | SMTP delegation | Native | Available |
| milter | Commercial | Sendmail milter emulator | External | v2.4 |
| ldap | Public | LDAP connector | External | v2.2
| dnsl | Public | DNS reverse lookup for white and black lists | External | v2.5
| spamassassin | Public | SpamAssassin service handler | External | v2.3
| rspamd | Commercial | rSPAM service handler | External | v2.4

## SMTP related protocols

| Name | License | Comment | Type | Status |
| :--- | :--- | :--- | :--- | :--- |
| spf | Public | Sender Policy Framework (RFC 7208) | Native | Available
| dkim | Public | DomainKeys Identified Mail (RFC 6376) | Native | Available
| dmarc | Public | Domain-based Message Authentication (RFC 7489) | Native | Available
| arc | Commercial | Authenticated Received Chain (RFC 8617) | External | v2.4
| opendkim | Commercial | OpenDKIM service adapter | External | v2.3
| opendmarc | Commercial| Handler for OpenDMARC service | External |  v2.4

## Delivery

| Name | License | Comment | Type | Status |
| :--- | :--- | :--- | :--- | :--- |
| transport | Public | Local and SMTP delivery | Internal | Available
| vsend | Commercial | Boost mass mailing performance | External | v2.3

## Performance and security

| Name | License | Comment | Type | Status |
| :--- | :--- | :--- | :--- | :--- |
| ddos | Public | Basic anti deny of service shield | External | v2.3
| vboost | Commercial | Reduce security infrastructure load | External | v2.6
| vddos | Commercial | Adaptive security shield | External | v2.7

## SQL databases

| Name | License | Comment | Type | Status |
| :--- | :--- | :--- | :--- | :--- |
| mysql | Public | MySQL/MariaDB connector | External | Available
| mongodb | Public | MongoDB connecter | External | v2.2

Do not hesitate to contact us for specific databases plugins.

## No-SQL and in-memory databases

| Name | License | Comment | Type | Status |
| :--- | :--- | :--- | :--- | :--- |
| csv | Public | Handler for Comma-Separated Values files | External | Available
| memc | Public | Memcached in-memory key-value store connector | External | v2.1
| redis | Commercial | Adaptor for Redis in-memory data structure store | External | v2.1
| bdb | Public | Berkeley DB connector | External | v2.2

## Misc

| Name | License | Comment | Type | Status |
| :--- | :--- | :--- | :--- | :--- |
| cmd | Public | Handler for Unix shell commands | Native | Available |
