# SCIM Gateway  

[![Build Status](https://app.travis-ci.com/jelhub/scimgateway.svg?branch=master)](https://app.travis-ci.com/github/jelhub/scimgateway) [![npm Version](https://img.shields.io/npm/v/scimgateway.svg?style=flat-square&label=latest)](https://www.npmjs.com/package/scimgateway)[![npm Downloads](https://img.shields.io/npm/dm/scimgateway.svg?style=flat-square)](https://www.npmjs.com/package/scimgateway) [![chat disqus](https://jelhub.github.io/images/chat.svg)](https://elshaug.xyz/docs/scimgateway#disqus_thread) [![GitHub forks](https://img.shields.io/github/forks/jelhub/scimgateway.svg?style=social&label=Fork)](https://github.com/jelhub/scimgateway)  

---  
Author: Jarle Elshaug  

Validated through IdP's:  

- Symantec/Broadcom/CA Identity Manager
- Microsoft Azure Active Directory  
- OneLogin  
- Okta 
- Omada 
- SailPoint/IdentityNow  
  
Latest news:  

- **BREAKING**: [SCIM Stream](https://elshaug.xyz/docs/scim-stream) is the modern way of user provisioning letting clients subscribe to messages instead of traditional IGA top-down provisioning. SCIM Stream includes **SCIM Stream Gateway**, the next generation SCIM Gateway that supports message subscription and automated provisioning
- Supporting OAuth Client Credentials authentication
- Major version v4.0.0. getUsers() and getGroups() replacing some deprecated methods. No limitations on filtering/sorting. Admin user access can be linked to specific baseEntities. New MongoDB plugin  
- ipAllowList for restricting access to allowlisted IP addresses or subnets e.g. Azure AD IP-range  
- General LDAP plugin configured for Active Directory  
- [PlugSSO](https://elshaug.xyz/docs/plugsso) using SCIM Gateway
- Authentication configuration allowing more than one admin user including option for readOnly
- Codebase moved from callback of h... to the the promise(d) land of async/await
- Supports configuration by environments and external files
- Health monitoring through "/ping" URL, and option for error notifications by email
- Azure AD user provisioning including license management e.g. Office 365, installed and configured within minutes!
- Includes API Gateway for none SCIM/provisioning - becomes what you want it to become   
- Running SCIM Gateway as a Docker container  

## Overview  
 
With SCIM Gateway we can manage users and groups by using REST based [SCIM](http://www.simplecloud.info/) 1.1 or 2.0 protocol. Gateway translates incoming SCIM requests and expose CRUD functionality (create, read, update and delete user/group) towards destinations using endpoint specific protocols. In other words, none SCIM-endpoints will become SCIM-endpoints. Gateway do not require SCIM to be used, it's also an API Gateway that could be used for other things than user provisioning.  

SCIM Gateway is a standalone product, however this document shows how the gateway could be used by products like Symatec/Broadcom/CA Identity Manager.

Using Identity Manager, we could setup one or more endpoints of type SCIM pointing to the gateway. Specific ports could then be used for each type of endpoint, and the SCIM Gateway would work like a "CA Connector Server" communicating with endpoints.

![](https://jelhub.github.io/images/ScimGateway.svg)

SCIM Gateway is based on the popular asynchronous event driven framework [Node.js](https://nodejs.dev/) using JavaScript. It is cloud and firewall friendly using REST webservices. Runs on almost all operating systems, and may load balance between hosts (horizontal) and cpu's (vertical).

**Following example plugins are included:**

* **Loki** (NoSQL Document-Oriented Database)  
SCIM Gateway becomes a standalone SCIM endpoint  
Demonstrates user provisioning towards document-oriented database  
Using [LokiJS](https://github.com/techfort/LokiJS) for a fast, in-memory document-oriented database (much like MongoDB/PouchDB)  
Default gives two predefined test users loaded using in-memory only (no persistence)  
Setting `{"persistence": true}` gives persistence file store (no test users)  
Example of a fully functional SCIM Gateway plugin  

* **MongoDB** (NoSQL Document-Oriented Database)  
Same as plugin "Loki", but using external MongoDB  
Shows how to implement a highly configurable multi tenant or multi endpoint solution through `baseEntity` in URL

* **SCIM** (REST Webservice)  
Demonstrates user provisioning towards REST-Based endpoint (type SCIM) 
Using plugin "Loki" as SCIM endpoint  
Can be used as SCIM version-gateway e.g. 1.1=>2.0 or 2.0=>1.1  
Can be used to chain several SCIM Gateway's  


* **Forwardinc** (SOAP Webservice)  
Demonstrates user provisioning towards SOAP-Based endpoint   
Using endpoint Forwardinc that comes with Broadcom/CA IM SDK (SDKWS) - [wiki.ca.com](https://docops.ca.com/ca-identity-manager/12-6-8/EN/programming/connector-programming-reference/sdk-sample-connectors/sdkws-sdk-web-services-connector/sdkws-sample-connector-build-requirements "wiki.ca.com")    
Shows how to implement a highly configurable multi tenant or multi endpoint solution through `baseEntity` in URL  

* **MSSQL** (MSSQL Database)  
Demonstrates user provisioning towards MSSQL database  

* **SAP HANA** (SAP HANA Database)  
Demonstrates SAP HANA specific user provisioning  

* **Azure AD** (REST Webservices)  
Azure AD user provisioning including Azure license management (App Service plans) e.g. Office 365  
Using Microsoft Graph API  
Using customized SCIM attributes according to Microsoft Graph API  
Includes Symantec/Broadcom/CA ConnectorXpress metafile for creating provisioning "Azure - ScimGateway" endpoint type  

* **LDAP** (Directory)  
Fully functional LDAP plugin  
Pre-configured for Microsoft Active Directory  
Using endpointMapper (like plugin-azure-ad) for attribute flexibility  

* **API** (REST Webservices)  
Demonstrates API Gateway/plugin functionality using post/put/patch/get/delete  
None SCIM plugin, becomes what you want it to become.  
Methods listed can also be used in standard SCIM plugins  
Endpoint complexity could be put in this plugin, and client could instead communicate through Gateway using your own simplified REST specification.  
One example of usage could be creation of tickets in ServiceDesk/HelpDesk and also the other way, closing a ticket could automatically approve/reject corresponding workflow in Identity Manager.  

    
## Installation  

#### Install Node.js  

Node.js is a prerequisite and have to be installed on the server.  

[Download](https://nodejs.org/en/download/) the windows installer (.msi 64-bit) and install using default options.  

#### Install SCIM Gateway  

Open a command window (run as administrator)  
Create your own package directory e.g. c:\my-scimgateway and install SCIM Gateway within this package.

	mkdir c:\my-scimgateway
	cd c:\my-scimgateway
	npm init -y
	npm install scimgateway

**c:\\my-scimgateway** will now be `<package-root>` 
 
index.js, lib and config directories containing example plugins have been copied to your package from the original scimgateway package located under node_modules.  

If internet connection is blocked, we could install on another machine and copy the `<package-root>` folder.


#### Startup and verify default Loki plugin 

	node c:\my-scimgateway
	
	Start a browser

	http://localhost:8880/ping
	=> Health check with a "hello" response

	http://localhost:8880/Users  
	http://localhost:8880/Groups 
	=> Logon using gwadmin/password and two users and groups should be listed  

	http://localhost:8880/Users/bjensen
	http://localhost:8880/Groups/Admins
	or
	http://localhost:8880/Users?filter=userName eq "bjensen"
	http://localhost:8880/Groups?filter=displayName eq "Admins"
	=> Lists all attributes for specified user/group

    http://localhost:8880/Groups?filter=displayName eq "Admins"&excludedAttributes=members
    http://localhost:8880/Groups?filter=members.value eq "bjensen"&attributes=id,displayName,members.value
    http://localhost:8880/Users?filter=userName eq "bjensen"&attributes=userName,id,name.givenName
    http://localhost:8880/Users?filter=meta.created ge "2010-01-01T00:00:00Z"&attributes=userName,name.familyName,meta.created
    http://localhost:8880/Users?filter=emails.value co "@example.com"&attributes=userName,name.familyName,emails&sortBy=name.familyName&sortOrder=descending
    => Filtering and attribute examples

	"Ctrl + c" to stop the SCIM Gateway

For more functionality using browser (post/patch/delete) a REST extension/add-on is needed. 

>Tip, take a look at mocha test scripts located in `node_modules\scimgateway\test\lib`  


#### Upgrade SCIM Gateway  

Not needed after a fresh install  

Check if newer versions are available: 

	cd c:\my-scimgateway
	npm outdated

Lists current, wanted and latest version. No output on screen means we are running the latest version.

The best and easiest way to upgrade is renaming existing scimgateway package folder, create a new one and do a fresh installation. After the installation you copy `index.js, config and lib folder` (your customized plugins) from your previous installation to the new installation. You should also read the version history to see if your custom plugins needs to be updated.

Alternatives are:  

Upgrade to latest minor version:  

	cd c:\my-scimgateway
	npm install scimgateway

Note, always backup/copy c:\\my-scimgateway before upgrading. Custom plugins and corresponding configuration files will not be affected.  

To force a major upgrade (version x.\*.\* => y.\*.\*) that will brake compability with any existing custom plugins, we have to include the `@latest` suffix in the install command: `npm install scimgateway@latest`

##### Avoid (re-)adding the files created during `postinstall`

When maintaining a set of modifications it useful to disable the postinstall operations to keep your changes intact by setting the property `scimgateway_postinstall_skip = true` in `.npmrc` or by setting environment `SCIMGATEWAY_POSTINSTALL_SKIP = true`  

## Configuration  

**index.js** defines one or more plugins to be started. We could comment out those we do not need. Default configuration only starts the loki plugin.  
  
	const loki = require('./lib/plugin-loki')
	// const mongodb = require('./lib/plugin-mongodb')
	// const scim = require('./lib/plugin-scim')
	// const forwardinc = require('./lib/plugin-forwardinc')
	// const mssql = require('./lib/plugin-mssql')
	// const saphana = require('./lib/plugin-saphana')  // prereq: npm install hdb
	// const azureAD = require('./lib/plugin-azure-ad')
	// const ldap = require('./lib/plugin-ldap')
	// const api = require('./lib/plugin-api')

Each endpoint plugin needs a JavaScript file (.js) and a configuration file (.json). **They both must have the same naming prefix**. For SAP Hana endpoint we have:  
>lib\plugin-saphana.js  
>config\plugin-saphana.json


Edit specific plugin configuration file according to your needs.  
Below shows an example of config\plugin-saphana.json  
  
	{
	  "scimgateway": {
	    "port": 8884,
	    "localhostonly": false,
        "scim": {
          "version": "2.0",
          "customSchema": null,
          "skipTypeConvert" : false,
          "usePutSoftSync" : false
        },
        "log": {
          "loglevel": {
            "file": "debug",
            "console": "error"
          },
          "customMasking": []
        },
        "auth": {
          "basic": [
            {
              "username": "gwadmin",
              "password": "password",
              "readOnly": false,
              "baseEntities": []
            }
          ],
          "bearerToken": [
            {
              "token": null,
              "readOnly": false,
              "baseEntities": []
            }
          ],
          "bearerJwtAzure": [
            {
              "tenantIdGUID": null,
              "readOnly": false,
              "baseEntities": []
            }
          ],
          "bearerJwt": [
            {
              "secret": null,
              "publicKey": null,
              "options": {
                "issuer": null
               },
              "readOnly": false,
              "baseEntities": []
            }
          ],
          "bearerOAuth": [
            {
              "client_id": null,
              "client_secret": null,
              "readOnly": false,
              "baseEntities": []
            }
          ]
        },
	    "certificate": {
	      "key": null,
	      "cert": null,
	      "ca": null,
	      "pfx": {
	        "bundle": null,
	        "password": null
	      }
	    },
	    "ipAllowList": [],
	    "emailOnError": {
	      "smtp": {
	        "enabled": false,
	        "host": null,
	        "port": 587,
	        "proxy": null,
	        "authenticate": true,
	        "username": null,
	        "password": null,
	        "sendInterval": 15,
	        "to": null,
	        "cc": null
	      }
	    }
	  },
	  "endpoint": {
	    "host": "hostname",
	    "port": 30015,
	    "username": "username",
	    "password": "password",
	    "saml_provider": "saml_provider_name"
	  }
	}


Configuration file have two main JSON objects: `scimgateway` and `endpoint`  

Definitions in `scimgateway` object have fixed attributes, but values can be modified. This object is used by the core functionality of the SCIM Gateway.  

Definitions in `endpoint` object are customized according to our plugin code. Plugin typically need this information for communicating with endpoint  

- **port** - Gateway will listen on this port number. Clients (e.g. Provisioning Server) will be using this port number for communicating with the gateway.  

- **localhostonly** - true or false. False means gateway accepts incoming requests from all clients. True means traffic from only localhost (127.0.0.1) is accepted (gateway must then be installed on the CA Connector Server).  

- **scim.version** - "1.1" or "2.0". Default is "2.0". For Symantec/Broadcom/CA Identity Manager "1.1" should be used.  

- **scim.customSchema** - filename of JSON file located in `<package-root>\config\schemas` containing custom schema attributes, see configuration notes 

- **scim.skipTypeConvert** - true or false, default false. Multivalue attributes supporting types e.g. emails, phoneNumbers, ims, photos, addresses, entitlements and x509Certificates (but not roles, groups and members) will be become "type converted objects" when sent to modifyUser and createUser. This for simplicity of checking attributes included and also for the endpointMapper method (used by plugin-ldap and plugin-azure-ad), e.g.: 

		"emails": {
		  "work": {"value": "jsmith@example.com", "type": "work"},
		  "home": {"value": "", "type": "home", "operation": "delete"},
		  "undefined": {"value": "jsmith@hotmail.com"}
		}  

        skipTypeConvert set to true gives attribute "as-is": array, allow duplicate types including blank, but values to be deleted have been marked with "operation": "delete"
  
		"emails": [
		  {"value": "jsmith@example.com", "type": "work"},
		  {"value": "john.smith.org", "type": "home", "operation": "delete"},
		  {"value": "jsmith@hotmail.com"}
		]  


- **scim.usePutSoftSync** - true or false, default false. `PUT /Users/bjensen` will replace the user bjensen with body content. If body contains groups, usePutSoftsync=true will prevent removing any existing groups that are not included in body.groups   

- **log.loglevel.file** - off, error, info, or debug. Output to plugin-logfile e.g. `logs\plugin-saphana.log`  

- **log.loglevel.console** - off, error, info, or debug. Output to stdout and errors to stderr.   

- **log.customMasking** - array of attributes to be masked e.g. `"customMasking": ["SSN", "weight"]`. By default SCIM Gateway includes masking of some standard attributes like password.  

- **auth** - Contains one or more authentication/authorization methods used by clients for accessing gateway - may also include:
  - **auth.xx.readOnly** - true/false, true gives read only access - only allowing `GET` requests for corresponding admin user
  - **auth.xx.baseEntities** - array containing one or more `baseEntity` allowed for this user e.g. ["client-a"] - empty array allowing all.  
  **Methods are disabled by setting corresponding admin user to null or remove methods not used**  

- **auth.basic** - Array of one ore more basic authentication objects - Basic Authentication with **username**/**password**. Note, we set a clear text password that will become encrypted when gateway is started.  

- **auth.bearerToken** - Array of one or more bearer token objects - Shared token/secret (supported by Azure). Clear text value will become encrypted when gateway is started.  

- **auth.bearerJwtAzure** - Array of one or more JWT used by Azure SyncFabric. **tenantIdGUID** must be set to Azure Active Directory Tenant ID.  

- **auth.bearerJwt** - Array of one or more standard JWT objects. Using **secret** or **publicKey** for signature verification. publicKey should be set to the filename of public key or certificate pem-file located in `<package-root>\config\certs`. Clear text secret will become encrypted when gateway is started. **options.issuer** is mandatory. Other options may also be included according to jsonwebtoken npm package definition.   

- **auth.bearerOAuth** - Array of one or more Client Credentials OAuth configuration objects. **`client_id`** and **`client_secret`** are mandatory. client_secret value will become encrypted when gateway is started. OAuth token request url is **/oauth/token** e.g. http://localhost:8880/oauth/token  

- **certificate** - If not using TLS certificate, set "key", "cert" and "ca" to **null**. When using TLS, "key" and "cert" have to be defined with the filename corresponding to the primary-key and public-certificate. Both files must be located in the `<package-root>\config\certs` directory e.g:  
  
		"certificate": {
		  "key": "key.pem",
		  "cert": "cert.pem",
		  "ca": null
		}  
  
    Example of how to make a self signed certificate:  

		openssl req -nodes -newkey rsa:2048 -x509 -sha256 -days 3650 -keyout key.pem -out cert.pem -subj "/O=Testing/OU=SCIM Gateway/CN=<FQDN>" -config "<path>\openssl.cnf"

    `<FQDN>` is Fully Qualified Domain Name of the host having SCIM Gateway installed
  
    Note, when using Broadcom/CA Provisioning, the "certificate authority - CA" also have to be imported on the Connector Server. For self-signed certificate CA and the certificate (public key) is the same.  

    PFX / PKCS#12 bundle can be used instead of key/cert/ca e.g: 

        "pfx": {
          "bundle": "certbundle.pfx",
          "password": "password"
        }

	Note, we should normally use certificate (https) for communicating with SCIM Gateway unless we install ScimGatway locally on the manager (e.g. on the CA Connector Server). When installed on the manager, we could use `http://localhost:port` or `http://127.0.0.1:port` which will not be passed down to the data link layer for transmission. We could then also set {"localhostonly": true}  

- **ipAllowList** - Array of one or more IPv4/IPv6 subnets (CIDR) allowed for incoming traffic.  E.g. using Azure AD as IdP, we would like to restrict access to IP addresses used by Azure AD. Azure IP-range can be downloaded from: [https://azureipranges.azurewebsites.net](https://azureipranges.azurewebsites.net), enter **AzureActiveDirectory** in the search list and select JSON download. Copy the "addressPrefixes" array content and paste into ipAllowList array. CIDR single IP-host syntax is a.b.c.d/32. Note, front-end HTTP proxy or a load balancer must include **X-Forwarded-For** header. Configuration example:  

        "ipAllowList": [
          "13.66.60.119/32",
          "13.66.143.220/30",
          ...
          "2603:1056:2000::/48",
          "2603:1057:2::/48"
        ]

- **emailOnError** - Contains configuration for sending error notifications by email. Note, only the first error will be sent until sendInterval have passed
- **emailOnError.smtp.enabled** - true or false, value set to true will enable email notifications
- **emailOnError.smtp.host** - Mailserver e.g. "smtp.office365.com"
- **emailOnError.smtp.port** - Port used by mailserver e.g. 587, 25 or 465
- **emailOnError.smtp.proxy** - If using mailproxy e.g. "http://proxy-host:1234"
- **emailOnError.smtp.authenticate** - true or false, set to true will use username/password authentication
- **emailOnError.smtp.username** - Mail account for authentication and also the sender of the email, e.g. "user@outlook.com"
- **emailOnError.smtp.password** - Mail account password
- **emailOnError.smtp.sendInterval** - Mail notifications on error are deferred until sendInterval **minutes** have passed since the last notification. Default 15 minutes
- **emailOnError.smtp.to** - Comma separated list of recipients email addresses e.g: "someone@example.com"
- **emailOnError.smtp.cc** - Comma separated list of cc email addresses

- **endpoint** - Contains endpoint specific configuration according to our **plugin code**.    
 
#### Configuration notes

- Setting environment variable `SEED` will override default password seeding logic.  
- All configuration can be set based on environment variables. Syntax will then be `"process.env.<ENVIRONMENT>"` where `<ENVIRONMENT>` is the environment variable used. E.g. scimgateway.port could have value "process.env.PORT", then using environment variable PORT.
- All configuration can be set based on corresponding JSON-content (dot notation) in external file using plugin name as parent JSON object. Syntax will then be `"process.file.<path>"` where `<path>` is the file used. E.g. endpoint.password could have value "process.file./var/run/vault/secrets.json"  
- Indivudual Secrets can be contained in plain text files. Syntax will then be `"process.text.<path>"` where `<path>` is the file which contains raw (`UTF-8`) character value. E.g. endpoint.password could have value "process.text./var/run/vault/endpoint.password". This enables that the config file itself be loaded from a ConfigMap while specific values are mounted either from `secrets.json` style files as mentioned above OR from traditional secrets files mounted in the file system, one value per file.

	Example:  

		{
		  "scimgateway": {
		    ...
		    "port": "process.env.PORT",
		    ...
		    "loglevel": {
		      "file": "process.env.LOG_LEVEL_FILE",
		      ...
		    "auth": {
		      "basic": [
		        {
		          "username": "process.file./var/run/vault/secrets.json",
		          "password": "process.file./var/run/vault/secrets.json"
		        },
		        ...
		      ],
		      "bearerJwt": [
		         "secret": "process.text./var/run/vault/jwt.secret",
		         "publicKey": "process.text./var/run/vault/jwt.pub",
				 ...
			  ],
		      ...
		    },
		  "endpoint": {
		    ...
		    "username": "process.file./var/run/vault/secrets.json",
		    "password": "process.file./var/run/vault/secrets.json",
		    ...
		  }
		}  


	secrets.json for plugin-forwardinc - example (dot notation):  
  
		{
		  "plugin-forwardinc.scimgateway.auth.basic[0].username": "gwadmin",
		  "plugin-forwardinc.scimgateway.auth.basic[0].password": "password",
		  "plugin-forwardinc.endpoint.username": "superuser",
		  "plugin-forwardinc.endpoint.password": "secret"
		}  

- Custom schema attributes can be added by plugin configuration `scim.customSchema` having value set to filename of a JSON schema-file located in `<package-root>/config/schemas` e.g:  

		"scim": {
		  "version": "2.0",
		  "customSchema": "plugin-forwardinc-schema.json"
		},

	JSON file have following syntax:  

		[
		  { 
		    "name": "User",
		    "attributes": [...]
		  },
		  { 
		    "name": "Group",
		    "attributes": [...]
		  }
		]

	Where array `attributes` contains custom attribute objects according to SCIM 1.1 or 2.0 spesification e.g:  

		"attributes": [
		  {
		    "name": "musicPreference",
			"type": "string",
			"multiValued": false,
			"description": "Music Preferences",
			"readOnly": false,
			"required": false,
			"caseExact": false
		  },
		  {
		    "name": "populations",
			"type": "complex",
			"multiValued": true,
			"multiValuedAttributeChildName": "population",
			"description": "Population array",
			"readOnly": false,
			"required": false,
			"caseExact": false,
			"subAttributes": [
			  {
			    "name": "value",
			    "type": "string",
			    "multiValued": false,
			    "description": "Population value",
			    "readOnly": false,
			    "required": true,
			    "caseExact": false
			  }
			]
		  }
		]

	Note, custom schema attributes will be merged into core:1.0/2.0 schema, and names must not conflict with standard SCIM attribute names.


## Manual startup    

Gateway can now be started from a command window running in administrative mode

3 ways to start:

	node c:\my-scimgateway

	node c:\my-scimgateway\index.js

	<package-root>node .


<kbd>Ctrl</kbd>+<kbd>c</kbd> to stop  

## Automatic startup - Windows Task Scheduler  

Start Windows Task Scheduler (taskschd.msc), right click on "Task Scheduler Library" and choose "Create Task"  
 
	General tab:  
	-----------
	Name = SCIM Gateway
	User account = SYSTEM
	Run with highest privileges
	
	Triggers tab:
	-------------
	Begin the task = At startup
	
	Actions tab:
	------------
	Action = Start a program
	Program/script = c:\Program Files\nodejs\node.exe
	Arguments = c:\my-scimgateway

	Settings - tab:
	---------------
	Stop the task if runs longer than = Disabled (greyed out)

Verification:

- Right click task - **Run**, verify process node.exe (SCIM Gateway) can be found in the task manager (not the same as task scheduler). Also verify logfiles `<pakage-root>\logs`  
- Right click task - **End**, verify process node.exe have been terminated and disappeared from task manager   
- **Reboot** server and verify SCIM Gateway have been automatically started

## Running as a isolated virtual Docker container  
On Linux systems we may also run SCIM Gateway as a Docker image (using docker-compose)  

* Docker Pre-requisites:  
**docker-ce  
docker-compose**



- Install SCIM Gateway within your own package and copy provided docker files:

		mkdir /opt/my-scimgateway  
		cd /opt/my-scimgateway  
		npm init -y  
		npm install scimgateway  
		cp ./config/docker/* .  

	**docker-compose.yml**   <== Here is where you would set the exposed port and environment  
	**Dockerfile**   <== Main dockerfile  
	**DataDockerfile**   <== Handles volume mapping   
	**docker-compose-debug.yml** <== Debugging  



- Create a scimgateway user on your Linux VM.   

		adduser scimgateway

- Create a directory on your VM host for the scimgateway configs:  

		mkdir /home/scimgateway/config

- Copy your updated configuration file e.g. /opt/my-scimgateway/config/plugin-loki.json to /home/scimgateway/config.  Use scp to perform the copy.

	NOTE: /home/scimgateway/config is where all important configuration and loki datastore will reside outside of the running docker container.  If you upgrade scimgateway you won't lose your configurations and data.

- Build docker images and start it up  

		docker-compose up --build -d

	NOTE: Add the -d flag to run the command above detached.  

	Be sure to confirm that port 8880 is available with a simple http request

	If using default plugin-loki and we have configured `{"persistence": true}`, we could confirm scimgateway created loki.db:
	
		su scimgateway  
		cd /home/scimgateway/config  
		ls loki.db  

To list running containers information:  
`docker ps`

To list available images:  
`docker images`

To view the logs:  
`docker logs scimgateway`

To execute command within your running container:  
`docker exec scimgateway <bash command>`

To stop scimgateway:  
`docker-compose stop`

To restart scimgateway:  
`docker-compose start`

To debug running container (using Visual Studio Code):  
`docker-compose -f docker-compose.yml -f docker-compose-debug.yml up -d`  
Start Visual Studio Code and follow [these](https://code.visualstudio.com/docs/nodejs/nodejs-debugging) debugging instructions  

To upgrade scimgateway docker image (remove the old stuff before running docker-compose up --build):  

	docker rm scimgateway  
	docker rm $(docker ps -a -q); docker rmi $(docker images -q -f "dangling=true")  

## Azure Active Directory as IdP using SCIM Gateway  

Azure AD could do automatic user provisioning by synchronizing users towards SCIM Gateway, and gateway plugins will update endpoints.

Plugin configuration file must include **SCIM Version "2.0"** (scimgateway.scim.version) and either **Bearer Token** (scimgateway.auth.bearerToken[x].token) or **Azure Tenant ID GUID** (scimgateway.auth.bearerJwtAzure[x].tenantIdGUID) or both:  

	scimgateway: {
	  "scim": {
	    "version": "2.0",
	    ...
	  },
	  ...
	  "auth": {
        "bearerToken": [
          {
            "token": "shared-secret"
          }
        ],
        "bearerJwtAzure": [
          {
            "tenantIdGUID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          }
        ]
      }
      ...
	}

`token` configuration must correspond with "Secret Token" defined in Azure AD  
`tenantIdGUID` configuration must correspond with Azure Active Directory Tenant ID  

In Azure Portal:
`Azure-Azure Active Directory-Enterprise Application-<My Application>-Provisioning-Secret Token`  
Note, when "Secret Token" is left blank, Azure will use JWT (tenantIdGUID)

`Azure-Azure Active Directory-Overview-Tenant ID`

User mappings attributes between AD and SCIM also needs to be configured  

`Azure-Azure Active Directory-Enterprise Application-<My Application>-Provisioning-Edit attribute mappings-Mappings`

Azure AD default SCIM attribute mapping for **USER** must have:  

	userPrincipalName mapped to userName (matching precedence #1)  


Azure AD default SCIM attribute mapping for **GROUP** must have:  

	displayName mapped to displayName (matching precedence #1)  
	members mapped to members  



Some notes related to Azure AD:  

- Azure Active Directory SCIM [documentation](https://docs.microsoft.com/en-us/azure/active-directory/active-directory-scim-provisioning)  

- For using OAuth/JWT credentials, Azure configuration "Secret Token" (bearer token) should be blank. Plugin configuration must then include bearerJwtAzure.tenantIdGUID. Click "Test Connection" in Azure to verify

- Azure AD do a regular check for a "none" existing user/group. This check seems to be a "keep alive" to verify connection.

- Azure AD first checks if user/group exists, if not exist they will be created (no explore of all users like CA Identity Manager)  

- Deleting a user in Azure AD sends a modify user `{"active":"False"}` which means user should be disabled. This logic is default set in attribute mappings expression rule `Switch([IsSoftDeleted], , "False", "True", "True", "False")`. Standard SCIM "DELETE" method seems not to be used.  


## CA Identity Manager as IdP using SCIM Gateway  

Using Symantec/Broadcom/CA Identity Manger, plugin configuration file must include **SCIM Version "1.1"** (scimgateway.scim.version).  

In the Provisioning Manager we have to use  


`Endpoint type = SCIM (DYN Endpoint)`  

or create our own custom endpoint type based on this one  

SCIM endpoint configuration example for Loki plugin (plugin-loki)

	Endpoint Name = Loki-8880  
	User Name = gwadmin  
	Password = password  
	SCIM Authentication Method = HTTP Basic Authentication  
	SCIM Based URL = http://localhost:8880  

	or:  

	SCIM Based URL = http://localhost:8880/<baseEntity>

Username, password and port must correspond with plugin configuration file. For "Loki" plugin it will be `config\plugin-loki.json`  

"SCIM Based URL" refer to the FQDN (or localhost) having SCIM Gateway installed. Portnumber must be included. Use HTTPS instead of HTTP if SCIM Gateway configuration includes certificates. 

"baseEntity" is optional. This is a parameter used for multi tenant or multi endpoint solutions. We could create several endpoints having same base url with unique baseEntity. e.g:  

http://localhost:8880/client-a  
http://localhost:8880/client-b

Each baseEntity should then be defined in the plugin configuration file with custom attributes needed. Please see examples in plugin-forwardinc.json

IM 12.6 SP7 (and above) also supports pagination for SCIM endpoint (data transferred in bulks - endpoint explore of users). Loki plugin supports pagination. Other plugin may ignore this setting.  


## Azure Active Directory provisioning  
Using plugin-azure-ad we could do user provisioning towards Azure AD including license management e.g. O365  

For testing purposes we could get an Azure free account and in addition the free Office 365 for testing license management through Azure.

There are two alternative ways of configuring Azure AD. Alternative #1 is probably best and easiest  


### Azure AD configuration 

- Logon to [Azure](https://portal.azure.com) as global administrator  
- Azure Active Directory - App registrations
	- Click "New registration"
	- Name = SCIM Gateway Inbound
	- Select: Accounts in this organizational directory only
	- Click "Register"
	- Overview:
		- Copy "Application (client) ID"
		- Copy "Directory (tentant) ID"
	- Certificates & secrets:
		- Click "New client secret"
		- Description = SCIM Gateway Inbound secret#1
		- Select an appropriate "Expires"
		- Click "Add"
		- Copy "Value" of the new secret that was created
	- API permissions: - Add a permission - Microsoft Graph - Application permissions
		- Optionally remove any defaults included e.g. User.Read		
		- Click "Add a permission"
		- Microsoft Graph
		- Application permissions
		- Directory - Directory.ReadWriteAll
		- Organization - Organization.ReadWrite.All
		- Click "Add permissions"  
		Note, we also have to go to Enterprise application to grant these consents  
- Azure Active Directory - Enterprise applications - SCIM Gateway Inbound
	- Permissions:
		- Click "Grant admin consent for [tenant name]"
		- In the logon dialog, logon as global administrator
		- In permissions request dialog, click "Accept"
		- Click "Refresh", directory and organization permissions are now listed and OK


**For some odd reasons Application needs to be member of "User administrator" for having privileges to manage office/mobile phone on users that is member of any administrator roles** 

Also note, enable/disable user (accountEnabled - through Graph API) will fail if user have an "Administrator" role other than above mentioned "User Administrator" e.g. "Group Administrator"/"Application Administrator". To be sure we can enable/disable all users,  application needs to be member of **"Global administrator"** - 62e90394-69f5-4237-9190-012177145e10.  
 
- Azure Active Directory - Roles and administration
	- Click on role **"User administrator"**
	- Click "Add assignments"
	- Search: SCIM Gateway Inbound (application name)
	- Select the application that shows up and click "Add"

### SCIM Gateway configuration  

**Edit index.js**  
Uncomment startup of plugin-azure-ad, other plugins could be comment out if not needed

	const azureAD = require('./lib/plugin-azure-ad')

**Edit plugin-azure-ad.json**

Note, for Symantec/Broadcom/CA Provisioning we have to use SCIM version 1.1 
 
	scimgateway: {
	  "scim": {
	    "version": "1.1"
	  },

`username` and `password` used to connect the SCIM Gateway must be defined.  

        "auth": {
          "basic": [
            {
              "username": "gwadmin",
              "password": "password",
              "readOnly": false,
              "baseEntities": []
            }
          ],

Update `tenantIdGUID`, `clientID` and `clientSecret` according to what you copied from the previous Azure AD configuration.  
  
If using proxy, set proxy.host to `"http://<FQDN-ProxyHost>:<port>"` e.g `"http://proxy.mycompany.com:3128"`  

	"endpoint": {
	  "entity": {
	    "undefined": {
	      "tenantIdGUID": "DomainName or DirectoryID (GUID)",
	      "clientId": "Application ID",
	      "clientSecret": "Generated application key value",
          "proxy": {
            "host": null,
            "username": null,
            "password": null
          }
	    }
	  }
	}

Note, clientSecret and any proxy.password will become encrypted in this file on the first Azure connection.  

For multi-tenant or multi-endpoint support, we may add several entities:

	"endpoint": {
	  "entity": {
	    "undefined": {
			...
	    },
	    "client-a": {
			...
	    },
	    "client-b": {
			...
	    }
	  }
	}

For additional details, see baseEntity description.  

Note, we should normally use certificate (https) for communicating with SCIM Gateway unless we install gateway locally on the manager (e.g. on the CA Connector Server). When installed on the manager, we could use `http://localhost:port` or `http://127.0.0.1:port` which will not be passed down to the data link layer for transmission. We could then also set {"localhostonly": true}  

### Using Symantec/Broadcom/CA Provisioning   
Create a new endpoint type "Azure - ScimGateway"  

- Start SCIM Gateway
	- "const azureAD" must be uncomment in `index.js`
	- username, password and port defined in `plugin-azure-ad.json` must also be known 
- Start ConnectorXpress
- Setup Data Sources
	- Add
	- Layer7 (this is SCIM)
	- Name = SCIM Gateway-8881
	- Base URL = http://localhost:8881 (SCIM Gateway installed locally on Connector Server)  
- Add the new "Azure - ScimGateway" endpoint type
	- Metadata - Import - "my-scimgateway\node_modules\scimgateway\config\resources\Azure - ScimGateway.xml"
	- Select the datasource we created - SCIM Gateway-8881
	- Enter password for the user defined in datasource (e.g. gwadmin/password)  
	- On the right - expand Provisioning Servers - your server - and logon
	- Right Click "Endpoint Types", Create New Endpoint Type
		- You may use default name "Azure - ScimGateway" and click "OK" to create endpoint

Note, metafile "Azure - ScimGateway.xml" is based on CA "Azure - WSL7" with some minor adjustments like using Microsoft Graph API attributes instead of Azure AD Graph attributes.

**Provisioning Manager configuration**  
  
`Endpoint type = Azure - ScimGateway (DYN Endpoint)`  

Endpoint configuration example:

	Endpoint Name = AzureAD-8881  
	User Name = gwadmin  
	Password = password  
	SCIM Authentication Method = HTTP Basic Authentication  
	SCIM Based URL = http://localhost:8881  
	or  
	SCIM Based URL = http://localhost:8881/<baseEntity>  

For details, please see section "CA Identity Manager as IdP using SCIM Gateway"

## SCIM Gateway REST API 
      
	Create = POST http://localhost:8880/Users  
	(body contains the user information)
	
	Update = PATCH http://localhost:8880/Users/<id>
	(body contains the attributes to be updated)
	
	Search/Read = GET http://localhost:8880/Users?userName eq 
	"userID"&attributes=<comma separated list of scim-schema defined attributes>
	
	Search/explore all users:
	GET http://localhost:8880/Users?attributes=userName
	
	Delete = DELETE http://localhost:8880/Users/<id>

Discovery:

	GET http://localhost:8880/ServiceProviderConfigs
	Specification compliance, authentication schemes, data models.
	
	GET http://localhost:8880/Schemas
	Introspect resources and attribute extensions.

Note:  

- userName (mandatory) = UserID  
- id (mandatory) = Unique id. Could be set to the same as UserID but don't have to.  


## API Gateway    

SCIM Gateway also works as an API Gateway when using url `/api` or `/<baseEntity>/api`  

Following methods for the none SCIM based api-plugin are supported:  
  
		GET /api  
		GET /api?queries  
		GET /api/{id}  
		POST /api + body  
		PUT /api/{id} + body  
		PATCH /api/{id} + body  
		DELETE /api/{id}  

These methods can also be used in standard SCIM plugins  
Please see example plugin: **plugin-api.js**

 
## How to build your own plugins  
For JavaScript coding editor you may use [Visual Studio Code](https://code.visualstudio.com/ "Visual Studio Code") 

Preparation:

* Copy "best matching" example plugin e.g. `lib\plugin-mssql.js` and `config\plugin-mssql.json` and rename both copies to your plugin name prefix e.g. plugin-mine.js and plugin-mine.json (for SOAP Webservice endpoint we might use plugin-forwardinc as a template) 
* Edit plugin-mine.json and define a unique port number for the gateway setting  
* Edit index.js and add a new line for starting your plugin e.g. `let mine = require('./lib/plugin-mine');`  
* Start SCIM Gateway and verify. If using CA Provisioning you could setup a SCIM endpoint using the port number you defined  

Now we are ready for custom coding by editing plugin-mine.js
Coding should be done step by step and each step should be verified and tested before starting the next (they are all highlighted by comments in existing code).  

1. **Turn off group functionality** - getGroups to return empty response  
Please see plugin-saphana that do not use groups.
2. **getUsers** (test provisioning retrieve accounts)
4. **createUser** (test provisioning new account)
5. **deleteUser** (test provisioning delete account)
6. **modifyUser** (test provisioning modify account)
7. **Turn on group functionality** - getGroups having logic for returning groups if groups are supported  
7. **getGroups** (test provisioning retrieve groups)
8. **modifyGroup** (test provisioning modify group members)  
12. **createGroup** (test provisioning new group)
13. **deleteGroup** (test provisioning delete account)


Template used by CA Provisioning role should only include endpoint supported attributes defined in our plugin. Template should therefore have no links to global user for none supported attributes (e.g. remove %UT% from "Job Title" if our endpoint/code do not support title)  

CA Provisioning using default SCIM endpoint do not support SCIM Enterprise User Schema Extension (having attributes like employeeNumber, costCenter, organization, division, department and manager). If we need these or other attributes not found in CA Provisioning, we could define our own by using the free-text "type" definition in the multivalue entitlements or roles attribute. In the template entitlements definition, we could for example define type=Company and set value to %UCOMP%. Please see plugin-forwardinc.js using Company as a multivalue "type" definition.  

Using CA Connector Xpress we could create a new SCIM endpoint type based on the original SCIM. We could then add/remove attributes and change from default assign "user to groups" to assign "groups to user". There are also other predefined endpoints based on the original SCIM. You may take a look at "ServiceNow - WSL7" and "Zendesk - WSL7". 


For project setup:  

* Datasource =  Layer7 (CA API) - this is SCIM  
* Layer7 Base URL = SCIM Gateway url and port (SCIM Base URL)  
* Authentication = Basic Authentication  
(connect using gwadmin/password defined in plugin config-file)

### How to change "user member of groups" to "group member of users"  

Using Connector Xpress based on the original SCIM endpoint.

Delete defaults:  
Group - Associations - with User Account  
Group - Attributes - members  
User Account - Attributes - Group Membership

Create new attribute:  
User Account - Attributes: Groups - Flexi DN - Multivalue - **groups**

Create User - Group associations:  
User Account - Accociations - **Direct association with = Group**  
User Account - Accociations - with Group

Note, "Include a Reverse Association" - not needed if we don't need Group object functionality e.g list/add/remove group members

User Attribute = **Physical Attribute = Groups**  
Match Group = By Attribute = ID

Objects Must Exist  
Use DNs in Attribute = activated (toggled on)  

Include a Reverse Association (if needed)  
Group Attribute = **Virtual Attribute = User Membership**  
Match User Account = By Attribute = User Name  

Note, groups should be capability attribute (updated when account is synchronized with template):  
advanced options - **Synchronized** = enabled (toggled on)

## Methods 

Plugins should have following initialization:  

	// mandatory plugin initialization - start
	const path = require('path')
	let ScimGateway = null
	try {
	  ScimGateway = require('scimgateway')
	} catch (err) {
	  ScimGateway = require('./scimgateway')
	}
	let scimgateway = new ScimGateway()
	let pluginName = path.basename(__filename, '.js')
	let configDir = path.join(__dirname, '..', 'config')
	let configFile = path.join(`${configDir}`, `${pluginName}.json`)
	let config = require(configFile).endpoint
	let validScimAttr = [] // empty array - all attrbutes are supported by endpoint
	// add any external config process.env and process.file
	config = scimgateway.processExtConfig(pluginName, config)
	// mandatory plugin initialization - end


### getUsers  

	scimgateway.getUsers = async (baseEntity, getObj, attributes) => {
	    let ret = {
	        "Resources": [],
	        "totalResults": null
	    }
		...
		return ret
	}  

* baseEntity = Optional for multi-tenant or multi-endpoint support (defined in base url e.g. `<baseurl>/client1` gives baseEntity=client1)  
* getObj = { attribute: <>, operator: <>, value: <>, rawFilter: <>, startIndex: <>, count: <> }
	* attribute, operator and value are set when using "simpel filtering", e.g. getObj.attribute='userName', getObj.operator='eq' and getObj.value='bjensen', but not for advanced filtering having and/or/not
	* rawFilter is always set when filtering is used
	* startIndex = Pagination - The 1-based index of the first result in the current set of search results  
	* count = Pagination - Number of elements to be returned in the current set of search results  
*  attributes = array of attributes to be returned - if empty, all supported attributes should be returned
* ret:   
ret.Resources = array filled with user objects according to getObj/attributes, we could normally include all attributes having id and userName as mandatory e.g [{"id": "bjensen", "userName": "bjensen"}, {"id":"jsmith", "userName":"jsmith"}]  
ret.totalResults = if supporting pagination, then it should be set to the total numbers of elements (users), else set to null

### deleteUser  

	scimgateway.deleteUser = async (baseEntity, id) => {
		...
		return null
	} 

* id = user id to be deleted 
* return null: null if OK, else throw error  

### modifyUser  

	scimgateway.modifyUser = async (baseEntity, id, attrObj) => {
		...
		return null
	} 


* id = user id  
* attrObj = object containing userattributes to be modified according to scim standard  
Note, multi-value attributes excluding user attribute 'groups' are customized from array to object based on type  
* return null: null if OK, else throw error

### getGroups  

	scimgateway.getGroups = async (baseEntity, getObj, attributes) => {
	    let ret = {
	        "Resources": [],
	        "totalResults": null
	    }
		...
		return ret
	}  

* baseEntity = Optional for multi-tenant or multi-endpoint support (defined in base url e.g. `<baseurl>/client1` gives baseEntity=client1)  
* getObj = { attribute: <>, operator: <>, value: <>, rawFilter: <>, startIndex: <>, count: <> }
	* attribute, operator and value are set when using "simpel filtering", e.g. getObj.attribute='displayName', getObj.operator='eq' and getObj.value='Admins', but not for advanced filtering having and/or/not
	* rawFilter is always set when filtering is used
	* startIndex = Pagination - The 1-based index of the first result in the current set of search results  
	* count = Pagination - Number of elements to be returned in the current set of search results  
*  attributes = array of attributes to be returned - if empty, all supported attributes should be returned
* ret:   
ret.Resources = array filled with group objects according to getObj/attributes, we could normally include all attributes having id, displayName and members as mandatory e.g [{"id":"Admins", "displayName":"Admins", members":[{"value":"bjensen"}]}, {"id":"Employees", "displayName":"Employees"}, "members":[{"value":"jsmith","display":"John Smith"}]]  
ret.totalResults = if supporting pagination, then it should be set to the total numbers of elements (users), else set to null


### createGroup  
	scimgateway.createGroup = async (baseEntity, groupObj) => {
		...
	    return null
	})

* groupObj = group object containing groupattributes according to scim standard  
groupObj.displayName contains the group name to be created
* return null: null if OK, else throw error  

### deleteGroup  
	scimgateway.deleteGroup = async (baseEntity, id) => {
		...
	    return null
	}

* id = group name (eg. Admins) to be deleted
* return null: null if OK, else throw error 

### modifyGroup  

	scimgateway.modifyGroup = async (baseEntity, id, attrObj) => {
		...
	    return null
	}

* id = group name (eg. Admins)  
* attrObj = object containing groupattributes to be modified according to scim standard  
**attrObj.members** (must be supported) = array of objects containing groupmembers modifications  
eg: {"value":"bjensen"},{"operation":"delete","value":"jsmith"}  
(adding bjensen and deliting jsmith from group)  
* return null: null if OK, else throw error  
If we do not support groups, then return null  


## License  
 
MIT © [Jarle Elshaug](https://www.elshaug.xyz)


## Change log  

### v4.1.9  

[Fixed]  
  
- plugin-azure-ad.json configuration file introduced in v.4.1.7 was missing passwordProfile attribute mappings
- Symantec/Broadcom/CA ConnectorXpress configuration file `config\resources\Azure - ScimGateway.xml` now using standard text on manager attribute instead of selection dialogbox.

### v4.1.8  

[Fixed]  
  
- endpointMap and Symantec/Broadcom/CA ConnectorXpress configuration file `config\resources\Azure - ScimGateway.xml` introduced in v.4.1.7 had some missing logic  

### v4.1.7  

**Note, this version breaks compability with previous versions of plugin-azure-ad**  

[Added]  

- endpointMap moved from scimgateway to plugin-azure-ad
- plugin-azure-ad.json configuration file now includes attribute mapping giving flexibility to add or customize AAD-SCIM attribute mappings
- Symantec/Broadcom/CA ConnectorXpress configuration file `config\resources\Azure - ScimGateway.xml` for defining the Azure endpoint, have been updated with some new attributes according to plugin-azure-ad.json attribute mappings

### v4.1.6  
[Added]
- Dependencies bump  

### v4.1.5  
[Added]  

Announcing some SCIM Gateway related news:  

- [SCIM Stream](https://elshaug.xyz/docs/scim-stream) is the modern way of user provisioning letting clients subscribe to messages instead of traditional IGA top-down provisioning. SCIM Stream includes **SCIM Stream Gateway**, the next generation SCIM Gateway that supports message subscription and automated provisioning


### v4.1.4  
[Fixed] 

- TypeConvert logic for multivalue attribute `addresses` did not correctly catch duplicate entries  
- PUT (Replace User) configuration `scim.usePutSoftsync=true` will also prevent removing any existing roles that are not included in body.roles ref. v4.1.3

### v4.1.3  
[Fixed] 

- createUser response did not include the id that was returned by plugin   

[Added] 

- PUT (Replace User) now includes group handling. Using configuration `scim.usePutSoftsync=true` will prevent removing any existing groups that are not included in body.groups

    Example:  

        PUT /Users/bjensen
        {
          ...
		  "groups": [
            {"value":"Employees","display":"Employees"},
            {"value":"Admins","display":"Admins"}
           ],
          ...
        }




### v4.1.2  
[Added] 

- endpointMapper supporting one to many mappings using a comma separated list of attributes in the `mapTo`  

    Configuration example:  

        "map": {
          "user": {
            "PersonnelNumber": {
              "mapTo": "id,userName",
              "type": "string"
            },
            ...
          }
        }
          

### v4.1.1  
[Added] 

- plugin-ldap support userFilter/groupFilter configuration for restricting scope  

    Configuration example:  

        {
          ...
          "userFilter": "(memberOf=CN=grp1,OU=Groups,DC=test,DC=com)(!(memberOf=CN=Domain Admins,CN=Users,DC=test,DC=com))",
          "groupFilter": "(!(cn=grp2))",
          ...
        }

### v4.1.0  
[Added] 

- Supporting OAuth Client Credentials authentication

    Configuration example:  

        "bearerOAuth": [
          {
            "client_id": "my_client_id",
            "client_secret": "my_client_secret",
            "readOnly": false,
            "baseEntities": []
          }
        ]


    In example above, client using SCIM Gateway must have OAuth configuration:  

        client_id = my_client_id
        client_secret = my_client_secret
        token request url = http(s)://<host>:<port>/oauth/token


### v4.0.1  
[Added] 

- create user/group supporting externalId
- plugin-restful renamed to plugin-scim
- plugin-ldap having improved SID/GUID support for Active Directory, also supporting domain map of userPrincipalName e.g. Azure AD => Active Directory
        
        "userPrincipalName": {
           "mapTo": "userName",
           "type": "string",
	       "mapDomain": {
	         "inbound": "test.onmicrosoft.com",
	         "outbound": "my-company.com"
        }

- postinstall copying example plugins may be skipped by setting the property `scimgateway_postinstall_skip = true` in `.npmrc` or by setting environment `SCIMGATEWAY_POSTINSTALL_SKIP = true`
- Secrets now also support key-value storage. The key defined in plugin configuration have syntax `process.text.<path>` where `<path>` is the file which contains raw (UTF-8) character value. E.g. configuration `endpoint.password` could have value `process.text./var/run/vault/endpoint.password`, and the corresponding file contains the secret. **Thanks to Raymond Augé**


### v4.0.0  
**[MAJOR]**  
 
- New `getUsers()` replacing deprecated exploreUsers(), getUser() and getGroupUsers()
- New `getGroups()` replacing deprecated exploreGroups(), getGroup() and getGroupMembers()
- Fully filter and sort support
- Authentication configuration may now include a baseEntities array containing one or more `baseEntity` allowed for corresponding admin user
- New plugin-mongodb, **thanks to Filipe Ribeiro and Miguel Ferreira (KEEP SOLUTIONS)**

Note, using this major version **require existing custom plugins to be upgraded**. If you do not want to upgrade your custom plugins, the old version have to be installed using: `npm install scimgateway@3.2.11`  

How to upgrade your custom plugins:  

	Replace: scimgateway.exploreUsers = async (baseEntity, attributes, startIndex, count) => {
	With: scimgateway.getUsers = async (baseEntity, getObj, attributes) => {

See comments in provided plugins regarding the new `getObj`. Also note that `attributes` is now an array and not a comma separated string like previous versions

In the very beginning, add:

	  // mandatory if-else logic - start
	  if (getObj.operator) {
	    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
	      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
	    } else if (getObj.operator === 'eq' && getObj.attribute === 'group.value') {
	      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
	      throw new Error(`${action} error: not supporting groups member of user filtering: ${getObj.rawFilter}`)
	    } else {
	      // optional - simpel filtering
	      throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
	    }
	  } else if (getObj.rawFilter) {
	    // optional - advanced filtering having and/or/not - use getObj.rawFilter
	    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
	  } else {
	    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
	  }
	  // mandatory if-else logic - end


In the new getUsers() replacing exploreUsers() "as-is", we then need some logic in the last "else" statement listed above.  
We also need to add logic from existing getGroup() and getGroupMembers()  
**Please have a look at provieded plugins to see different ways of doing this logic.**  


	Replace: scimgateway.exploreGroups = async (baseEntity, attributes, startIndex, count) => {
	With: scimgateway.getGroups = async (baseEntity, getObj, attributes) => {

In the very beginning, add:

	  // mandatory if-else logic - start
	  if (getObj.operator) {
	    if (getObj.operator === 'eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
	      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
	    } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') {
	      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
	      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
	    } else {
	      // optional - simpel filtering
	      throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
	    }
	  } else if (getObj.rawFilter) {
	    // optional - advanced filtering having and/or/not - use getObj.rawFilter
	    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
	  } else {
	    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
	  }
	  // mandatory if-else logic - end


In the new getGroups() replacing exploreGroups() "as-is", we then need some logic in the last "else" statement listed above.  
We also need to add logic from existing getGroup() and getGroupMembers()  
**Please have a look at provieded plugins to see different ways of doing this logic.**  


    Delete deprecated exploreUsers(), getUser(), getGroupUsers(), exploreGroups(), getGroup() and getGroupMembers()


### v3.2.11  
[Fixed] 

- errorhandling related to running scimgateway as unikernel 

### v3.2.10  
[Fixed] 

- for SCIM 2.0 exploreUsers/exploreGroups now includes schemas/resourceType on each object in the Resources response. This may be required by som IdP's.  

[Added]
- Dependencies bump  

### v3.2.9  
[Fixed] 

- plugin-loki pagination fix

### v3.2.8  
[Fixed] 

- plugin-ldap `objectGUID` introduced in v.3.2.7 had some missing logic   

### v3.2.7  
[Added] 

- plugin-ldap supports using Active Directory `objectGUID` instead of `dn` mapped to `id`  
  configuration example:
        
        "objectGUID": {
          "mapTo": "id",
          "type": "string"
        }

[Fixed]  

- Return 500 on GET handler error instead of 404  
  **Thanks to Nipun Dayanath**
- createUser/createRole response now includes id retrieved by getUser/getRole instead of using posted userName/displayName value

### v3.2.6  
[Fixed]  

- bearerJwt authentication missing public key handling
- plugin-azure-ad getGroup did not return all members when group had more than 100 members (Azure page size is 100). getGroup now using paging 

### v3.2.5  
[Fixed]  

- default "type converted object" logic may fail on requests that includes a mix of type and blank type. Now blank type will be converted to type "undefined", and all types must be unique within the same request. "type converted object" logic can be turned off by configuration `scim.skipTypeConvert = true`  
- plugin-loki supporting type = "undefined"

[Added]  

- new configuration `scim.skipTypeConvert` allowing overriding the default behaviour "type converted object" when set to true. See attribute list for details  
- `scimgateway.isMultivalue` used by plugin-loki have been changed, and **custom plugins using this method must be updated**    
 
        old syntax:
        scimgateway.isMultivalue('User', key)

        new syntax:
        scimgateway.isMultiValueTypes(key) 

### v3.2.4  
[Fixed]  

- plugin-loki some code cleanup  

### v3.2.3  
[Fixed]  

- PUT was not according to the SCIM specification  
- plugin-mssql broken after dependencies bump v3.1.0  
- plugin-loki getUser using `find` instead of `findOne` to ensure returning unique user    

### v3.2.2  
[Fixed]  

- plugins missing logic for handling the virtual readOnly user attribute `groups` (when `"user member of groups"`) e.g. GET /Users/bjensen should return all user attributes including the virtual `groups` attribute. Now this user attribute will be automatically handled by scimgateway if not included in the plugin response.  
- Pre and post actions onAddGroups/onRemoveGroups introduced in v.3.2.0 has been withdrawn  

[Added]  

- scimgateway will do plugin response filtering according to requested attributes/excludedAttributes  


### v3.2.1  
[Fixed]  

- plugin-azure-ad updating businessPhones (Office phone) broken after v3.2.0  
- plugin-azure-ad listing groups for user did also include Azure roles  
- SCIM v2.0 none core schema attributes handling
- response not always including correct schemas   

[Added]  

- roles now using array instead of objects based on type. **Note, this may break your custom plugins if roles logic are in use**  

### v3.2.0  
[Added]  

- ipAllowList for restricting access to allowlisted IP addresses or subnets e.g. Azure AD IP-range  
	Configuration example:  
	
        "ipAllowList": [
          "13.66.60.119/32",
          "13.66.143.220/30",
          ...
          "2603:1056:2000::/48",
          "2603:1057:2::/48"
        ]

- Example plugins now configured for SCIM v2.0 instead of v1.1  

	New configuration:  
	
	    "scim": {
            "version": "2.0"
	    }
	
	Old configuration:  
	
	    "scim": {
            "version": "1.1"
	    }


### v3.1.0  
[Added]  

- plugin-ldap a general LDAP plugin pre-configured for Microsoft Active Directory. Using endpointMapper logic (like plugin-azure-ad) for attribute flexibility   
- Pre and post actions onAddGroups/onRemoveGroups can be configured and needed logic to be  defined in plugin method `pre_post_Action`  
- Dependencies bump  

### v3.0.8  
[Fixed]  

- plugin-azure-ad delete account fails in v3.x

### v3.0.7  
[Fixed]  

- Using proxy configuration broken in v3.x

### v3.0.6  
[Fixed]   

- Dependencies bump

### v3.0.4  
[Added] 

- Pagination request having startIndex but no count, now sets count to default 200 and may be overridden by plugin.

### v3.0.3  
[Fixed] 

- GET /Users?startIndex=1&count=100 with no attributes filter included did not work

### v3.0.2  
[Fixed] 

- SCIM v2.0 PUT did not work.

### v3.0.1  
[Added] 

- getApi supports body (apiObj).

	Old syntax:  
	
	    scimgateway.getApi = async (baseEntity, id, apiQuery) => {
	
	New syntax:  
	
	    scimgateway.getApi = async (baseEntity, id, apiQuery, apiObj) => {


### v3.0.0  
**[MAJOR]**  

- getUser/getGroup now using parameter getObj giving more flexibility  
- deprecated modifyGroupMembers - now using modifyGroup
- deprecated configuration `scimgateway.scim.customUniqueAttrMapping` - replaced by getObj logic
- loglevel=off turns of logging
- Auth methods allowing more than one user/object including option for readOnly
- Includes latest versions of module dependencies 
  

**[UPGRADE]**  

Note, this is a major upgrade (^2.x.x => ^3.x.x) that will brake compatibility with any existing custom plugins. To force a major upgrade, suffix `@latest` must be include in the npm install command, but it's recommended to do a fresh install and copy any custom plugins instead of upgrading an existing package  

Old syntax:  

    scimgateway.getUser = async (baseEntity, userName, attributes) => {
    scimgateway.getGroup = async (baseEntity, displayName, attributes) => {
    scimgateway.modifyGroupMembers = async (baseEntity, id, members) => {

New syntax:  

    scimgateway.getUser = async (baseEntity, getObj, attributes) => {
      const userName = getObj.identifier // gives v2.x compatibility

    scimgateway.getGroup = async (baseEntity, getObj, attributes) => {
      const displayName = getObj.identifier // gives v2.x compatibility

    scimgateway.modifyGroup = async (baseEntity, id, attrObj) => {
      // attrObj.members corresponds to members in deprecated modifyGroupMembers

getUser comments:  
getObj = `{ filter: <filterAttribute>, identifier: <identifier> }`  
e.g: getObj = `{ filter: 'userName', identifier: 'bjensen'}`  
filter: userName and id must be supported  

getGroup comments:  
getObj = `{ filter: <filterAttribute>, identifier: <identifier> }`  
e.g: getObj = `{ filter: 'displayName', identifier: 'GroupA' }`  
filter: displayName and id must be supported  

**Please see provided example plugins**  

Using the new getObj parameter gives more flexibility in the way of lookup a user e.g:  
`http://localhost:8880/Users?filter=emails.value eq "jsmith@example.com"&attributes=userName,name.givenName`  
getObj = `{ filter: 'emails.value', identifier: 'jsmith@example.com'}`  
attributes = `'userName,name.givenName'`

Configuration file, auth settings have changed and now using arrays allowing more than one user/object to be set. `"readOnly": true` can also be set for allowing read only access for a spesific user (does not apply to bearerJwtAzure).

New syntax is:

    "auth": {
      "basic": [
        {
          "username": "gwadmin",
          "password": "password",
          "readOnly": false
        }
      ],
      "bearerToken": [
        {
          "token": null,
          "readOnly": false
        }
      ],
      "bearerJwtAzure": [
        {
          "tenantIdGUID": null
        }
      ],
      "bearerJwt": [
        {
          "secret": null,
          "publicKey": null,
          "options": {
            "issuer": null
          },
          "readOnly": false
        }
      ]
    }


### v2.1.13  
[Fixed] 

- Plugin configuration referring to an external configuration file using an array did not work.  

### v2.1.11  
[Fixed] 

- Log masking of xml (SOAP) messages.  


### v2.1.10  
[Added] 

- Log masking of custom defined attributes.  
  customMasking may include an array of attributes to be masked  
  e.g. `"customMasking": ["SSN", "weight"]`
- Note, configurationfiles must be changed (old syntax still supported)  
  old syntax:  

        "loglevel": {
          "file": "debug",
          "console": "error"
        },
  new syntax:  

        "log": {
          "loglevel": {
            "file": "debug",
            "console": "error"
          },
          "customMasking": []
        },
  By default SCIM Gateway includes masking of standard attributes like password

### v2.1.9  
[Fixed] 

- AAD as IdP broken after content-type validation introduced in v2.1.7
- AAD as IdP, none gallery app support
- Incorrect SCIM 2.0 multivalue converting
- plugin-saphana not correctly ported to v2.x  

**Thanks to Luca Moretto**  

### v2.1.8  
[Fixed] 

- plugin-mssql not correctly ported to v2.x, and some config syntax for this plugin have also changed in newer releases of dependencies.

### v2.1.7  
[Fixed] 

- Validates content-type when body is included
- Case insensitive log-masking
- Plugins now don't using deprecated `url.parse`
- Misc cosmetics e.g. using const instead of let when not reassigned

### v2.1.6  
[Fixed] 

- plugin-azure-ad did not return correct error code (`err.name = 'DuplicateKeyError'`) when failing on creating a duplicate user

[Added]  

- Includes latest versions of module dependencies

### v2.1.4  
[Fixed] 

- Incorrect SCIM 2.0 error handling after v2.1.0
- For duplicate key error, setting `err.name = 'DuplicateKeyError'` now gives correct status code 409 instead of defult 500 (see plugin-loki.js)  

### v2.1.3  
[Fixed] 

- Standardized the API Gateway response (not SCIM related)
- Not allowing plugins to return password
- Colorize option now automatically turned off when using stdout/stderr redirect (configuration file `loglevel.colorize` is not needed)

### v2.1.2  
[Fixed]  

- SCIM 2.0 may use Operations.value as array and none array (issue #16) 

[Added]  

- Option for replacing mandatory userName/displayName attribute by configuring customUniqueAttrMapping  
- Includes latest versions of module dependencies

### v2.1.1  
[Fixed]  

- SCIM 2.0 may use Operations.value or Operation.value[] for PATCH syntax of the name object (issue #14)
- plugin-loki failed to modify a none existing object, e.g name object not included in Create User 

### v2.1.0  
[Added] 

- Custom schema attributes can be added by plugin configuration `scim.customSchema` having value set to filename of a JSON schema-file located in `<package-root>/config/schemas`

**[UPGRADE]**  

- Configurationfiles for custom plugins should be changed  
  old syntax:  

        "scimversion": "1.1",  
  new syntax:  

		"scim": {
	      "version": "1.1",
	      "customSchema": null
	    },
Note, "1.1" is default, if using "2.0" the new syntax must be used.


### v2.0.2  
[Fixed]  

- SCIM 2.0 incorrect response for user not found
- Did not mask logentries ending with newline


### v2.0.0  
**[MAJOR]**  

- Codebase moved from callback to async/await  
- Koa replacing Express  
- Some log enhancements  
- Deprecated cipher methods have been replaced  
- Plugin restful (REST) and 
- forwardinc (SOAP) includes failover logic based on endpoints defined in array baseUrls/baseServiceEndpoints. 

**[UPGRADE]**  

Note, this is a major upgrade (^1.x.x => ^2.x.x) and will brake compatibility with any existing custom plugins. To force a major upgrade, suffix `@latest` must be include in the npm install command, but it's recommended to do a fresh install and copy any custom plugins instead of upgrading an existing package  

	cd c:\my-scimgateway
	npm install scimgateway@latest

Custom plugins needs some changes (please see included example plugins)  

- `scimgateway.on(xxx, function (..., callback)` replaced with `scimgateway.xxx = async (...)` returning a result or throwing an error
- Rest and SOAP using `doRequest` method having endpoint failover logic through array `baseUrls/baseServiceEndpoints` defined in corresponding plugin configuration file.  
- Additional argument `attributes` included in exploreUsers and exploreGroups method
- Proxy configuration includes option for user/password  
- Encrypted passwords in configuration files needs to be reset to clear text passwords  


### v1.0.20  
[Fixed]  

- HTTP status code 200 and totalResults set to value of 0 when using SCIM 2.0 filter user/group and no resulted user/group found. SCIM 1.1 still using  status code 404.

**[UPGRADE]**  

- For custom plugins to be compliant with SCIM 2.0, the `getUser` and `getGroup` methods needs to be updated. If user/group not found then return `callback(null, null)` instead of callback(err)  


### v1.0.19  
[Fixed]  

- Fix related to external configuration (ref. v1.0.18) when running multiple plugins  

### v1.0.18  
[Added]  

- Includes latest versions of module dependencies
- Loglevel configuration for file and console now separated
- Loglevel colorize option (value false could be useful when redirecting console output)  
- All configuration can be set based on environment variables
- All configuration can be set based on correspondig json-content in external file (supports also dot notation)

**[UPGRADE]**  

- Configurationfiles for custom plugins should be changed  
  old syntax:  

        loglevel: "debug"
  new syntax:  

        "loglevel": {
          "file": "debug",
          "console": "error",
          "colorize": true
        }

### v1.0.14  
[Fixed]  

- Some multiValued attributes not correctly handled (e.g. addresses)  
   
### v1.0.13  
[Fixed]  

- plugin-azure-ad: New version of "Azure - ScimGateway.xml" fixing CA IM RoleDefGenerator problem (related to creating and importing screens in CA IM)  

**[UPGRADE]**  

- Use CA ConnectorXpress, import "Azure - ScimGateway.xml" and deploy/redeploy endpoint

### v1.0.12  
[Fixed]  

- Incorrect logging of Express stream messages (type info) when running multiple plugins    

### v1.0.11  
[Fixed]  

- plugin-azure-ad: proxy configuration did not work    


### v1.0.10  
[Fixed]  

- An issue with pagination fixed  

### v1.0.9  
[Added]  

- Cosmetics, changed emailOnError logic - now emitted by logger

### v1.0.8  
[Added]  

- Support health monitoring using the "/ping" URL with a "hello" response, e.g. http://localhost:8880/ping. Useful for frontend load balancing/failover functionality  
- Option for error notifications by email  

**[UPGRADE]**  

- Configuration files for custom plugins must include the **emailOnError** object for enabling error notifications by email. Please see the syntax in provided example plugins and details described in the "Configuration" section of this document.
  
 
### v1.0.7  
[Added]  

- Docker now using node v.9.10.0 instead of v.6.9.2
- Minor log cosmetics

### v1.0.6  
[Fixed]  

- Azure AD plugin, failed to create user when licenses (app Service plans) was included  

### v1.0.5  
[Added]  

- Supporting GET /Users, GET /Groups, PUT method and delete groups  
- After more than 3 invalid auth attempts, response will be delayed to prevent brute force

[Fixed]  

- Some minor compliance fixes  

**Thanks to ywchuang** 

### v1.0.4  
[Added]  

- Plugin for Azure AD now supports paging for retrieving users and groups. Any existing metafile used by CA ConnectorXpress ("Azure - ScimGateway.xml") must be re-deployed.

[Fixed]  

- Don't use deprecated existsSync in postinstallation 

### v1.0.3  
[Fixed]  

- Undefined root url not handled correctly after v1.0.0

### v1.0.2  
[Fixed]  

- License and group defined as capability attributes in metafile used by CA ConnectorXpress regarding plugin-azure-ad     

### v1.0.1  
[Fixed]  

- Mocha test script did not terminate after upgrading from 3.x to 4.x of Mocha  

### v1.0.0  
[Added]  

- New plugin-azure-ad.js for Azure AD user provisioning including Azure license management e.g. Office 365
- Includes latest versions of module dependencies
- Module hdb (for SapHana) and saml is not included by default anymore and therefore have to be manually installed if needed. 

**[UPGRADE]**  
Method `getGroupMembers` must be updated for all custom plugins

Replace:  

	scimgateway.on('getGroupMembers', function (baseEntity, id, attributes, startIndex, count, callback) {
	...
	let ret = {
	'Resources' : [],
	'totalResults' : null
	}
	...
	ret.Resources.push(userGroup)
	...
	callback(null, ret)


With:  

	scimgateway.on('getGroupMembers', function (baseEntity ,id ,attributes, callback) {
	...
	let arrRet = []
	...
	arrRet.push(userGroup)
	...
	callback(null, arrRet)

### v0.5.3  
[Added]  

- Includes api gateway/plugin for general none provisioning  
  - GET /api
  - GET /api?queries
  - GET /api/{id}
  - POST /api + body
  - PUT /api/{id} + body
  - PATCH /api/{id} + body
  - DELETE /api/{id}
- plugin-api.js demonstrates api functionallity (becomes what you want it to become) 


### v0.5.2  
[Added]  

- One or more of following authentication/authorization methods are accepted:  
  - Basic Authentication
  - Bearer token - shared secret
  - Bearer token - Standard JSON Web Token (JWT)
  - Bearer token - Azure JSON Web Token (JWT) 

**[UPGRADE]**  

- Configuration files for custom plugins `config/plugin-xxx.json` needs to be updated regarding the new `scimgateway.auth` section:  
	- Copy scimgateway.auth section from one of the example plugins
	- Copy existing scimgateway.username value to new auth.basic.username value
	- Copy existing scimgateway.password value to new auth.basic.username value
	- Copy existing scimgateway.oauth.accesstoken value to new auth.bearer.token value
	- Delete scimgateway.username
	- Delete scimgateway.password
	- Delete scimgateway.oauth


### v0.4.6  
[Added]  

- Document updated on how to run SCIM Gateway as a Docker container  
- `config\docker` includes docker configuration examples  
**Thanks to Charley Watson and Jeffrey Gilbert**  


### v0.4.5  
[Added]  

- Environment variable `SEED` overrides default password seeding  
- Setting SCIM Gateway port to `"process.env.XXX"` lets environment variable XXX define the port  
- Don't validate config-file port number for numeric value (Azure AD - iisnode using a name pipe for communication) 

**[UPGRADE]**  

- Configuration files for custom plugins `config/plugin-xxx.json` needs to be updated:  
	- Encrypted passwords needs to be reset to clear text passwords
	- Start SCIM Gateway and passwords will become encrypted  

### v0.4.4  
[Added]  

- NoSQL Document-Oriented Database plugin: `plugin-loki`  
This plugin now replace previous `plugin-testmode`  
**Thanks to Jeffrey Gilbert**  
- Minor code/comment reorganizations in provided plugins  
- Minor adjustments to multi-value logic introduced in v0.4.0  

**[UPGRADE]**  

- Delete depricated `lib/plugin-testmode.js` and `config/plugin-testmode.json`
- Edit index.js, replace tesmode with loki   

### v0.4.2
[Fixed]  

- plugin-restful minor adjustments to multivalue and cleared attributes logic introduced in v0.4.0  

### v0.4.1
[Added]  

- Mocha test scripts for automated testing of plugin-testmode  
- Automated tests run on Travis-ci.org (click on build badge) 
- **Thanks to Jeffrey Gilbert**


  
[Fixed]  

- Minor adjustments to multi-value logic introduced in v0.4.0

### v0.4.0  
[Added]  

- Not using the SCIM standard for handling multivalue attributes and cleared attributes. Changed from array to object based on type. This simplifies plugin-coding for multivalue attributes like emails, phoneNumbers, entitlements, ...
- Module dependencies updated to latest versions  

**[UPGRADE]**  

- Custom plugins using multivalue attributes needs to be updated regarding methods createUser and modifyUser. Please see example plugins for details.

### v0.3.8  
[Fixed]  

- Minor changes related to SCIM specification

### v0.3.7  
[Added]  

- PFX / PKCS#12 certificate bundle is supported

### v0.3.6  
[Added]  

- SCIM Gateway used by Microsoft Azure Active Directory is supported
- SCIM version 2.0 is supported
- Create group is supported  

**[UPGRADE]**  

- For custom plugins to support create group, they needs to be updated regarding listener method `scimgateway.on('createGroup',...` Please see example plugins for details. 



### v0.3.5  
[Fixed]  

- plugin-mssql not included in postinstall  

### v0.3.4  
[Added]  

- MSSQL example plugin: `plugin-mssql` 
- Changed multivalue logic in example plugins, now using `scimgateway.getArrayObject`  

[Fixed]  

- Minor changes related to SCIM specification


### v0.3.3  
[Fixed]  

- Logic for handling incorrect pagination request to avoid endless loop conditions (there is a pagination bug in CA Identity Manager v.14)  
- Pagination now supported on getGroupMembers  

**[UPGRADE]**  

- Custom plugins needs to be updated regarding listener method `scimgateway.on('getGroupMembers',...` New arguments have been added "startIndex" and "count". Also a new return variable "ret". Please see example plugins for details.

### v0.3.2  
[Fixed]  

- Minor changes related to SCIM specification

### v0.3.1  
[Added]  

- REST Webservices example plugin: `plugin-restful` 

### v0.3.0  
[Added]  

- Preferred installation method changed from "global" to "local"
- `<Base URL>/[baseEntity]` for multi tenant or multi endpoint flexibility  
- plugin-forwardinc includes examples of baseEntity, custom soap header and signed saml assertion  
- Support groups defined on user object "group member of user"  
- New module dependendcies included: saml, async and callsite  


**[UPGRADE]**  

- Use "fresh" install and restore any custom plugins. Custom plugins needs to be updated. Listener method names have changed and method must include "baseEntity" - please see example plugins.

### v0.2.2 - v0.2.8  
[Doc]

- Minor readme changes and version bumps

### v0.2.1
[Fixed]

- plugin-forwardinc explore of empty endpoint

### v0.2.0  
Initial version


