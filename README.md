
# ScimGateway  

[![Build Status](https://travis-ci.org/jelhub/scimgateway.svg)](https://travis-ci.org/jelhub/scimgateway) [![npm Version](https://img.shields.io/npm/v/scimgateway.svg?style=flat-square&label=latest)](https://www.npmjs.com/package/scimgateway)[![npm Downloads](https://img.shields.io/npm/dt/scimgateway.svg?style=flat-square)](https://www.npmjs.com/package/scimgateway) [![chat disqus](https://jelhub.github.io/images/chat.svg)](https://elshaug.xyz/md/scimgateway#disqus_thread) [![GitHub forks](https://img.shields.io/github/forks/jelhub/scimgateway.svg?style=social&label=Fork)](https://github.com/jelhub/scimgateway)  

---  
Author: Jarle Elshaug  

Validated on:  

- CA Identity Manager
- Microsoft Azure Active Directory  

Latest news:  

- Azure AD user provisioning including license management (e.g. Office 365), installed and configured within minutes!
- API gateway for general none provisioning (becomes what you want it to become)
- Authentication includes standard JSON Web Token (JWT) and Azure JWT
- Running ScimGateway as a Docker container  

## Overview  
 
With ScimGateway we could do user management by using REST based [SCIM](http://www.simplecloud.info/) protocol, and the gateway will translate and communicate towards destinations using endpoint specific protocols.  

ScimGateway is a standalone product, however this document shows how the gateway could be used by products like CA Identity Manager.

Using CA Identity Manager, we could setup one or more endpoints of type SCIM pointing to the gateway. Specific ports could then be used for each type of endpoint, and the ScimGateway would work like a "CA Connector Server" communicating with endpoints.

![](https://jelhub.github.io/images/ScimGateway.svg)

Instead of using IM-SDK for building our own integration for none supported endpoints, we can now build new integration based on ScimGateway plugins. ScimGateway works with IM as long as IM supports SCIM.

ScimGateway is based on the popular asynchronous event driven framework [Node.js](https://nodejs.org/en/about/) using javascripts. It is firewall friendly using REST webservices. Runs on almost all operating systems, and may loadbalance between hosts (horizontal) and cpu's (vertical). Could even be uploaded and run as a cloud application.

**Following example plugins are included:**

* **Loki** (NoSQL Document-Oriented Database)  
Gives a SCIM endpoint located on ScimGateway  
Demonstrates user provisioning towards document-oriented database  
Using [LokiJS](http://lokijs.org) for a fast, in-memory document-oriented database (much like MongoDB/PouchDB)  
Default gives two predefined test users loaded using in-memory only (no persistence)  
Setting {"persistence": true} gives persistence file store (no test users)  
Supporting explore, create, delete, modify and list users (including groups)  
Example of a fully functional ScimGateway plugin  

* **RESTful** (REST Webservice)  
Demonstrates user provisioning towards REST-Based endpoint   
Using plugin "Loki" as a REST endpoint

* **Forwardinc** (SOAP Webservice)  
Demonstrates user provisioning towards SOAP-Based endpoint   
Using endpoint Forwardinc that comes with CA IM SDK (SDKWS) - please see [wiki.ca.com](https://docops.ca.com/ca-identity-manager/12-6-8/EN/programming/connector-programming-reference/sdk-sample-connectors/sdkws-sdk-web-services-connector/sdkws-sample-connector-build-requirements "wiki.ca.com")    
Shows how to implement a higly configurable multi tenant or multi endpoint solution using "baseEntity" parameter  

* **MSSQL** (MSSQL Database)  
Demonstrates user provisioning towards MSSQL database  

* **SAP HANA** (SAP HANA Database)  
Demonstrates SAP HANA specific user provisioning  

* **Azure AD** (REST Webservices)  
Azure AD user provisioning including Azure license management e.g. O365  
Using Microsoft Graph API  
Using customized SCIM attributes according to Microsoft Graph API  
Includes CA ConnectorXpress metafile for creating "Azure - ScimGateway" endpoint  
  


* **API** (REST Webservies)  
Demonstrates api gateway functionality using post/put/patch/get/delete  
None SCIM plugin, becomes what you want it to become.  
Endpoint complexity could be put in this plugin, and client could instead communicate through ScimGateway using your own simplified REST specification.  
One example of usage could be creation of tickets in ServiceDesk/HelpDesk and also the other way, closing a ticket could automatically approve/reject corresponding workflow in Identity Manager (from REST to IM SOAP/TEWS).    

## Installation  

#### Install Node.js  

Node.js is a prerequisite and have to be installed on the server.  

[Download](https://nodejs.org/en/download/) the windows installer (.msi 64-bit) and install using default options.  

#### Install ScimGateway  

Open a command window (run as administrator)  
Create your own package directory e.g. C:\my-scimgateway and install ScimGateway within this package.

	mkdir c:\my-scimgateway
	cd c:\my-scimgateway
	npm init -y
	npm install scimgateway --save

Please **ignore any error messages** unless soap WSSecurityCert functionality is needed in your custom plugin code. Module soap installation of optional dependency 'ursa' that also includes 'node-gyp' then needs misc. prerequisites to bee manually be installed.


**c:\\my-scimgateway** will now be `<package-root>` 
 
index.js, lib and config directories containing example plugins have been copied to your package from the original scimgateway package located under node_modules.  

If internet connection is blocked, we could install on another machine and copy the scimgateway folder.


#### Startup and verify default Loki plugin 

	node c:\my-scimgateway
	
	Start a browser
	http://localhost:8880/Users?attributes=userName  

	Logon using gwadmin/password and two users should be listed  

	http://localhost:8880/Users/bjensen
	Lists all user attributes for specified user

	"Ctrl + c" to stop the scimgateway

For more functionality using browser (post/patch/delete) a REST extension/add-on is needed. 	

#### Upgrade ScimGateway  

Not needed after a fresh install  

Check if newer versions are available: 

	cd c:\my-scimgateway
	npm outdated

Lists current, wanted and latest version. No output on screen means we are running the latest version.

Upgrade to latest version:  

	cd c:\my-scimgateway
	npm install scimgateway@latest

Note, always backup/copy C:\\my-scimgateway before upgrading. Custom plugins and corresponding configuration files will not be affected.  

## Configuration  

**index.js** defines one or more plugins to be started. We could comment out those we do not need. Default configuration only starts the loki plugin.  
  
	const loki = require('./lib/plugin-loki')
	// const restful = require('./lib/plugin-restful')
	// const forwardinc = require('./lib/plugin-forwardinc')
	// const mssql = require('./lib/plugin-mssql')
	// const saphana = require('./lib/plugin-saphana')  // prereq: npm install hdb --save
	// const api = require('./lib/plugin-api')
	// const azureAD = require('./lib/plugin-azure-ad')

Each endpoint plugin needs a javascript file (.js) and a configuration file (.json). **They both must have the same naming suffix**. For SAP Hana endpoint we have:  
>lib\plugin-saphana.js  
>config\plugin-saphana.json


Edit specific plugin configuration file according to your needs.  
Below shows an example of config\plugin-saphana.json  
  
	{
	  "scimgateway": {
	    "scimversion": "1.1",
	    "loglevel": "debug",
	    "localhostonly": false,
	    "port": 8884,
	    "auth": {
	      "basic": {
	        "username": "gwadmin",
	        "password": "password"
	      },
	      "bearer": {
	        "token": null,
	        "jwt": {
	          "azure": {
	            "tenantIdGUID": null
	          },
	          "standard": {
	            "secret": null,
	            "publicKey": null,
	            "options": {
	              "issuer": null
	            }
	          }
	        }
	      }
	    },
	    "certificate": {
	      "key": null,
	      "cert": null,
	      "ca": null,
	      "pfx": {
	        "bundle": null,
	        "password": null
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


Attribute explanation:  

Definitions under "scimgateway" have fixed attributes but we can change the values. This section is used by the core functionality of the ScimGateway.  

Definitions under "endpoint" are used by endpoint plugin for communicating with endpoint and needs to be defined according to our code. 

- **scimversion** - 1.1 or 2.0. Default is 1.1. For Azure AD 2.0 should be used.  

- **loglevel** - error or debug. Output to console and logfile `logs\plugin-saphana.log` (debug not sent to console).  

- **localhostonly** - true or false. False means gateway accepts incoming requests from all clients. True means traffic from only localhost (127.0.0.1) is accepted (gateway must then be installed on the CA Connector Server).  

- **port** - (**) Gateway will listen on this port number. Clients (e.g. Provisioning Server) will be using this port number for communicating with the gateway. For endpoint the port is the port number used by plugin for communicating with SAP Hana.  

- **auth** - Contains one or more authentication/authorization methods used by clients for accessing gateway. **Methods are disabled by setting corresponding attributes to null**  

- **auth.basic** - Basic Authentication with **username**/**password**. Note, we set a clear text password and when gateway is started password will become encrypted and updated in the configuration file.  

- **auth.bearer** - Contains misc bearer token methods for authorization of client requests.  

- **auth.bearer.token** - Shared token/secret (supported by Azure). Clear text value will become encrypted when gateway is started.  

- **auth.bearer.jwt** - Contains misc JSON Web Token (JWT) methods for authorization.  

- **auth.bearer.jwt.azure** - JWT used by Azure SyncFabric. **tenantIdGUID** must be set to Azure Active Directory Tenant ID.  

- **auth.bearer.jwt.standard** - Standard JWT. Using **secret** or **publicKey** for signature verification. publicKey should be set to the filename of public key or certificate pem-file located in `<package-root>\config\certs`. Clear text secret will become encrypted when gateway is started. **options.issuer** is mandatory. Other options may also be included according to jsonwebtoken npm package definition.   

- **certificate** - If not using SSL/TLS certificate, set "key", "cert" and "ca" to **null**. When using SSL/TLS, "key" and "cert" have to be defined with the filename corresponding to the primary-key and public-certificate. Both files must be located in the `<package-root>\config\certs` directory e.g:  
  
		"certificate": {
		  "key": "key.pem",
		  "cert": "cert.pem",
		  "ca": null
		}  
  
    Example of how to make a self signed certificate:  

		openssl req -nodes -newkey rsa:2048 -x509 -sha256 -days 3650 -keyout key.pem -out cert.pem -subj "/O=Testing/OU=ScimGateway/CN=<FQDN>" -config "<path>\openssl.cnf"

    `<FQDN>` is Fully Qualified Domain Name of the host having ScimGateway installed
  
    Note, when using CA Provisioning, the "certificate authority - CA" also have to be imported on the Connector Server. For self-signed certificate CA and the certificate (public key) is the same.  

    PFX / PKCS#12 bundle can be used instead of key/cert/ca e.g: 

        "pfx": {
          "bundle": "certbundle.pfx",
          "password": "password"
        }

	Note, we should normally use certificate (https) for communcating with ScimGateway unless we install ScimGatway locally on the manager (e.g. on the CA Connector Server). When installed on the manager, we could use `http://localhost:port` or `http://127.0.0.1:port` which will not be passed down to the data link layer for transmission. We could then also set {"localhostonly": true}  
 
- **endpoint** - Contains endpoint specific configuration according to our plugin code.  
  

  (**) Both port number and password encryption seed may be overridden by setting environment variables before starting the gateway.  Setting environment variable `SEED` will override default password seed. Setting the ScimGateway port in the configuration file to `"process.env.XXX"` where XXX is the environment variable let gateway use environment variable for port configuration. This could be useful in cloud systems e.g:  

	    "scimgateway": {
			...
	        "port": "process.env.PORT",
			...
		}


## Manual startup    

Gateway can now be started from a command window running in administrative mode

3 ways to start:

	node c:\my-scimgateway

	node c:\my-scimgateway\index.js

	<package-root>node .


<kbd>Ctrl</kbd>+<kbd>c</kbd> to to stop  

## Automatic startup - Windows Task Scheduler  

Start Windows Task Scheduler (taskschd.msc), right click on "Task Scheduler Library" and choose "Create Task"  
 
	General tab:  
	-----------
	Name = ScimGateway
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

- Right click task - **Run**, verify process node.exe (ScimGateway) can be found in the task manager (not the same as task scheduler). Also verify logfiles `<pakage-root>\logs`  
- Right click task - **End**, verify process node.exe have been terminated and disappeared from task manager   
- **Reboot** server and verify ScimGateway have been automatically started

## Running as a isolated virtual Docker container  
On Linux systems we may also run ScimGateway as a Docker image (using docker-compose)  

* Docker Pre-requisites:  
**docker-ce  
docker-compose**



- Install ScimGateway within your own package and copy provided docker files:

		mkdir /opt/my-scimgateway  
		cd /opt/my-scimgateway  
		npm init -y  
		npm install scimgateway --save  
		cp ./config/docker/* .  

	**docker-compose.yml**   <== Here is where you would set the exposed port and environment  
	**Dockerfile**   <== Main dockerfile  
	**DataDockerfile**   <== Handles volume mapping   
	**docker-compose-debug.yml** <== Debugging  



- Create a scimgateway user on your Linux VM.   

		adduser scimgateway

- Create a directory on your VM host for the scimgateway configs:  

		mkdir /home/scimgateway/config

- Copy your updated configuration file e.g. scimgateway/config/plugin-loki.json to /home/scimgateway/config.  Use scp to perform the copy.

	NOTE: /home/scimgateway/config is where all of important configuration and loki datastore will reside outside of the running docker container.  If you upgrade scimgateway you won't loose you configurations and data.

- Build docker images and start it up  

		docker-compose up --build -d

	NOTE: Add the -d flag to run the command above detached.  

	Be sure to confirm that port 8880 is available with a simple http request

	If using default plugin-loki and we have configured `{"persistence": true}`, we could confirm scimgateway created loki.db:
	
		su scimgateway  
		cd /home/scimgateway/config  
		ls loki.db  
	

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

## CA Provisioningserver - SCIM Endpoint  

Using the CA Provisioning Manager we have to configure  
  
`Endpoint type = SCIM (DYN Endpoint)`  

SCIM endpoint configuration example for Loki plugin (plugin-loki)

	Endpoint Name = Loki  
	User Name = gwadmin  
	Password = password  
	SCIM Authentication Method = HTTP Basic Authentication  
	SCIM Based URL = http://localhost:8880  

	or:  

	SCIM Based URL = http://localhost:8880/<baseEntity>

Username, password and port must correspond with plugin configuration file. For "Loki" plugin it will be `config\plugin-loki.json`  

"SCIM Based URL" refer to the FQDN (or localhost) having ScimGateway installed. Portnumber must be included. Use HTTPS instead of HTTP if ScimGateway-configuration includes certificates. 

"baseEntity" is optional. This is a parameter used for multi tenant or multi endpoint solutions. We could create several endpoints having same base url with unique baseEntity. e.g:  

http://localhost:8880/clientA  
http://localhost:8880/clientB

Each baseEntity should then be defined in the plugin configuration file with custom attributes needed. Please see examples in plugin-forwardinc.json

IM 12.6 SP7 (and above) also supports pagination for SCIM endpoint (data transferred in bulks - endpoint explore of users). Loki plugin supports pagination. Other plugin may ignore this setting.  

## ScimGateway REST API 
      
	Create = POST http://example.com:8880/Users  
	(body contains the user information)
	
	Update = PATCH http://example.com:8880/Users/<id>
	(body contains the attributes to be updated)
	
	Search/Read = GET http://example.com:8880/Users?userName eq 
	"userID"&attributes=<comma separated list of scim-schema defined attributes>
	
	Search/explore all users:
	GET http://example.com:8880/Users?attributes=userName
	
	Delete = DELETE http://example.com:8880/Users/<id>

Discovery:

	GET http://example.com:8880/ServiceProviderConfigs
	Specification compliance, authentication schemes, data models.
	
	GET http://example.com:8880/Schemas
	Introspect resources and attribute extensions.

Note:  

- userName (mandatory) = UserID  
- id (mandatory) = Unique id. Could be set to the same as UserID but don't have to.  

## SAP Hana endpoint  

	Get all users (explore):  
	select USER_NAME from SYS.USERS where IS_SAML_ENABLED like 'TRUE';
	
	Get a specific user:  
	select USER_NAME, USER_DEACTIVATED from SYS.USERS where USER_NAME like '<UserID>';
	
	Create User:  
	CREATE USER <UserID> WITH IDENTITY '<UserID>' FOR SAML PROVIDER <SamlProvider>;
	
	Delete user:  
	DROP USER <UserID>;
	
	Modify user (enable user):  
	ALTER USER <UserID> ACTIVATE;
	
	Modify user (disable user):  
	ALTER USER <UserID> DEACTIVATE;  

Postinstallation:  
  
	cd c:\my-scimgateway
	npm install hdb --save  


Only SAML users will be explored and managed

Supported template attributes:  

- User Name (UserID)
- Suspended (Enabled/Disabled)  

Currently no other attributes needed. Trying to update other attributes will then give an error message.  **The SCIM Provisioning template should therefore not include any other global user attribute references.**

SAP Hana converts UserID to uppercase. Provisioning use default lowercase. Provisioning template should therefore also convert to uppercase.

	User Name = %$$TOUPPER(%AC%)%

## Azure Active Directory endpoint  
Using plugin-azure-ad we could do user provisioning towards Azure AD including license management e.g. O365  

For testing purposes we could get an Azure free account and in addition the free Office 365 for testing license management through Azure.

**Azure AD prerequisites**  

- Logon to [Azure](https://portal.azure.com) as global administrator  
- Azure Active Directory - properties
	- Copy **"Directory ID"**  
	- or Azure Active Directory - Custom domain names (copy primary domain name)
- Azure Active Directory - App registrations - New application registration 
	- Name = newApp  
	- Application type = Web app API
	- Sign-on URL = http://localhost (not used)
	- Click "Create"
- Click "newApp"
	- Copy **"Application ID"**  
	- Required permissions - Windows Azure Active Directory
		-   Enable "APPLICATION PERMISSIONS" (all application sub categories enabled)
		-   Click "Save"
	-   Keys
		- Key description = Key1
		- Duration = Never expires
		- Click "Save"
		- Copy Key1 **"value"**" (client secret)

**Application needs to be member of "User Account Administrator" when running behalf of application rather than user** 
 
- Start Powershell command window
- Install the [Azure AD Module](https://docs.microsoft.com/en-us/powershell/msonline/) (if not already installed)  
	- Install-Module MSOnline
- Import-Module MSOnline
- Connect-MsolService (logon as a user having "Global administrator" role)   
- Get-MsolServicePrincipal -AppPrincipalId {Application ID}  
	- Copy ObjectId
- List all roles and find "User Account Administrator"  
	- Get-MsolRole  
- List current members of this role:
	- Get-MsOlRoleMember -RoleObjectId fe930be7-5e62-47db-91af-98c3a49a38b1
- Add application to "User Account Administrator" role:  
	- Add-MsolRoleMember -RoleName "User Account Administrator" -RoleMemberType ServicePrincipal -RoleMemberObjectId {ObjectIdOfServicePrincipal}  
- Verify:  
	- Get-MsOlRoleMember -RoleObjectId fe930be7-5e62-47db-91af-98c3a49a38b1  

**Edit index.js**  
Uncomment startup of plugin-azure-ad, other plugins could be comment out if not needed

	const azureAD = require('./lib/plugin-azure-ad')

**Edit plugin-azure-ad.json**

`Username` and `password` used to connect the ScimGateway must be defined.

Update `tenantIdGUID`, `clientID` and `clientSecret` according to Azure AD prerequisites configuration.  
  
If using proxy, set proxy to `"http://<FQDN-ProxyHost>:<port>"` e.g `"http://proxy.mycompany.com:3128"`  

	"endpoint": {
	  "entity": {
	    "undefined": {
	      "proxy": null,
	      "tenantIdGUID": "DomainName or DirectoryID (GUID)",
	      "clientId": "Application ID",
	      "clientSecret": "Generated application key value"
	    }
	  }
	}

Note, clientSecret will become encrypted in this file on the first Azure connection.  

For multi-tenant or multi-endpoint support, we may add several entities:

	"endpoint": {
	  "entity": {
	    "undefined": {
			...
	    }
	    "clientA": {
			...
	    }
	    "clientB": {
			...
	    }
	  }
	}

For additional details, see baseEntity description.  

Note, we should normally use certificate (https) for communicating with ScimGateway unless we install ScimGatway locally on the manager (e.g. on the CA Connector Server). When installed on the manager, we could use `http://localhost:port` or `http://127.0.0.1:port` which will not be passed down to the data link layer for transmission. We could then also set {"localhostonly": true}  

**For CA Provisioning, create endpoint type "Azure - ScimGateway"**  

- Start ScimGateway
	- "const azureAD" must be uncomment in `index.js`
	- username, password and port defined in `plugin-azure-ad.json` must also be known 
- Start ConnectorXpress
- Setup Data Sources
	- Add
	- Layer7 (this is SCIM)
	- Name = ScimGateway-8881
	- Base URL = http://localhost:8881 (ScimGateway installed locally on Connector Server)  
- Add the new "Azure - ScimGateway" endpoint type
	- Metadata - Import - "my-scimgateway\node_modules\scimgateway\resources\Azure - ScimGateway.xml"
	- Select the datasource we created - ScimGateway-8881
	- Enter password for the user defined in datasource (e.g. gwadmin/password)  
	- On the right - expand Provisioning Servers - your server - and logon
	- Right Click "Endpoint Types", Create New Endpoint Type
		- You may use default name "Azure - ScimGateway" and click "OK" to create endpoint

Note, metafile "Azure - ScimGateway.xml" is based on CA "Azure - WSL7" with some minor adjustments like using Microsoft Graph API attributes instead of Azure AD Graph attributes.

**Using the CA Provisioning Manager we have to configure**  
  
`Endpoint type = Azure - ScimGateway (DYN Endpoint)`  

Endpoint configuration example:

	Endpoint Name = Azure-AD-8881  
	User Name = gwadmin  
	Password = password  
	SCIM Authentication Method = HTTP Basic Authentication  
	SCIM Based URL = http://localhost:8881  
	or  
	SCIM Based URL = http://localhost:8881/<baseEntity>  

For details, please see section "CA Provisioningserver - SCIM Endpoint"


## Azure Active Directory using ScimGateway  

Azure AD could do automatic user provisioning by synchronizing users towards ScimGateway, and ScimGateway plugins will update endpoints.

Plugin configuration file must include scimversion "2.0" and either bearer.token or azure.tenantIdGUID (or both):  

	{
	  "scimversion": "2.0",
	  ...
	  "auth": {
	    ...
        "bearer": {
          "token": "shared-secret",
          "jwt": {
            "azure": {
              "tenantIdGUID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            },
	    ...
      },
	  ...
	}

`bearer.token` configuration must correspond with "Secret Token" defined in Azure AD  
`tenantIdGUID` configuration must correspond with Azure Active Directory Tenant ID  

In Azure Portal:
`Azure-Azure Active Directory-Enterprise Application-<My Application>-Provisioning-Secret Token`  
Note, when "Secret Token" is left blank, Azure will use JWT (tenantIdGUID)

`Azure-Azure Active Directory-Properties-Directory ID`

User mappings attributes between AD and SCIM also needs to be configured  

`Azure-Azure Active Directory-Enterprise Application-<My Application>-Provisioning-Mappings`

Azure AD default SCIM attribute mapping for **USER** have:  

	externalId mapped to mailNickname (matching precedence #1)  
	userName mapped to userPrincipalName  

ScimGateway accepts externalId (as matching precedence) instead of  userName, but `userName and externalId must be mapped to the same AD attribute` e.g:

	externalId mapped to mailNickname (matching precedence #1)  
	userName mapped to mailNickname  

	or:  

	externalId mapped to userPrincipalName (matching precedence #1)  
	userName mapped to userPrincipalName  


Azure AD default SCIM attribute mapping for **GROUP** have:  

	externalId mapped to displayName (matching precedence #1)  
	displayName mapped to mailNickname  

ScimGateway accepts externalId (as matching precedence) instead of displayName, but `displayName and externalId must then be mapped to the same AD attribute` e.g:  

	externalId mapped to displayName (matching precedence #1)
	displayName mapped to displayName

Some notes related to Azure AD:  

- Azure Active Directory SCIM [documentation](https://docs.microsoft.com/en-us/azure/active-directory/active-directory-scim-provisioning)  

- Use the "[old Portal]( https://manage.windowsazure.com)" for adding/creating your SCIM application.  Adding an application using the "[new Portal](https://portal.azure.com)" will not give an OAuth/JWT compatible app - only bearer token (Secret Token) will be used. After the app have been registered (passing the "Test phase"), we could start using the "new Portal"

- Azure AD do a regular check for a "none" existing user/group. This check seems to be a "keep alive" to verify connection.

- Azure AD first checks if user/group exists, if not exist they will be created (no explore of all users like CA Identity Manager)  

- Deleting a user in Azure AD sends a modify user `{"active":"False"}` which means user should be disabled. This logic is configured in attribute mappings. Standard SCIM "DELETE" method seems not to be used.  

## api-plugin    

ScimGateway supports following methods for the none SCIM based api-plugin:  
  
		GET /api  
		GET /api?queries  
		GET /api/{id}  
		POST /api + body  
		PUT /api/{id} + body  
		PATCH /api/{id} + body  
		DELETE /api/{id}  


 
## How to build your own plugins  
For javascript coding editor you may use [Visual Studio Code](https://code.visualstudio.com/ "Visual Studio Code") 

Preparation:

* Copy "best matching" example plugin e.g. `lib\plugin-loki.js` and `config\plugin-loki.json` and rename both copies to your plugin name prefix e.g. plugin-mine.js and plugin-mine.json (for SOAP Webservice endpoint we might use plugin-forwardinc as a template) 
* Edit plugin-mine.json and define a unique port number for the scimgateway setting  
* Edit index.js and add a new line for starting your plugin e.g. `var mine = require('./lib/plugin-mine');`  
* Start ScimGateway and verify. If using CA Provisioning you could setup a SCIM endpoint using the port number you defined  

Now we are ready for custom coding by editing plugin-mine.js
Coding should be done step by step and each step should be verified and tested before starting the next (they are all highlighted by comments in existing code).  

1. **Turn off group functionality** in getGroup, getGroupMembers, getGroupUsers and modifyGroupMembers  
Please see callback definitions in plugin-saphana that do not use groups.
2. **exploreUsers** (test provisioning explore users)
3. **getUser** (test provisioning retrieve account)
4. **createUser** (test provisioning new account)
5. **deleteUser** (test provisioning delete account)
6. **modifyUser** (test provisioning modify account)
7. **exploreGroups** (test provisioning explore groups)
8. **Turn on group functionality** (if supporting groups)
8. **getGroup** (test provisioning group list groups)
9. **getGroupMembers** (test provisioning retrieve account - group list groups)
10. **modifyGroupMembers** (test provisioning retrieve account - group add/remove groups)
11. **getGroupUsers** (if using "groups member of user")   
12. **createGroup** (test provisioning new group)  

Template used by CA Provisioning role should only include endpoint supported attributes defined in our plugin. Template should therefore have no links to global user for none supported attributes (e.g. remove %UT% from "Job Title" if our endpoint/code do not support title)  

CA Provisioning using default SCIM endpoint do not support SCIM Enterprise User Schema Extension (having attributes like employeeNumber, costCenter, organization, division, department and manager). If we need these or other attributes not found in CA Provisioning, we could define our own by using the free-text "type" definition in the multivalue entitlements or roles attribute. In the template entitlements definition we could for example define type=Company and set value to %UCOMP%. Please see plugin-forwardinc.js using Company as a multivalue "type" definition.  

Using CA Connector Xpress we could create a new SCIM endpoint type based on the original SCIM. We could then add/remove attributes and change  from default assign "user to groups" to assign "groups to user". There are also other predefined endpoints based on the original SCIM. You may take a look at "ServiceNow - WSL7" and "Zendesk - WSL7". 


For project setup:  

* Datasource =  Layer7 (CA API) - this is SCIM  
* Layer7 Base URL = ScimGateway url and port (SCIM Base URL)  
* Authentication = Basic Authentication  
(connect using gwadmin/password defined in plugin config-file)

### How to change "user member of groups" to "groups member of user"  

Using Connector Xpress based on the original SCIM endpoint.

Delete defaults:  
Group - Associations - with User Account  
User Account - Attributes - Group Membership

Create new attribute:  
User Account - Attributes: Groups - Flexi DN - Multivalue - **groups**

Create User - Group associations:  
User Account - Accociations - **Direct association with = Group**  
User Account - Accociations - with Group

Note, "Include a Reverse Association" - not needed if we don't need Group object functionality e.g list/add/remove group members

User Attribute = **Physical Attribute = Groups**  
Match Group = By Attribute = Name

Objects Must Exist  
Use DNs in Attribute = deactivated (toggled off)  

Include a Reverse Association (if needed)  
Group Attribute = **Virtual Attribute = User Membership**  
Match User Account = By Attribute = User Name  

Note, groups should be capability attribute (updated when account is synchronized with template):  
advanced options - **Synchronized** = enabled (toggled on)

## Methods 

Plugins should have following initialization:  

	// mandatory plugin initialization - start
	const path = require('path');
	let ScimGateway = null;
	try {
	    ScimGateway = require('scimgateway');
	} catch (err) {
	    ScimGateway = require('./scimgateway');
	}
	let scimgateway = new ScimGateway();
	let pluginName = path.basename(__filename, '.js');
	let configDir = path.join(__dirname, '..', 'config');
	let configFile = path.join(`${configDir}`, `${pluginName}.json`);
	let config = require(configFile).endpoint;
	let validScimAttr = []; // empty array - all attrbutes are supported by endpoint
	// mandatory plugin initialization - end


### exploreUsers  

	scimgateway.on('exploreUsers', function (baseEntity, startIndex, count, callback) {
	    var ret = {
	        "Resources": [],
	        "totalResults": null
	    }
		...
		callback(error, ret)
	})  

* baseEntity = Optional for multi-tenant or multi-endpoint support (defined in base url e.g. `<baseurl>/client1` gives baseEntity=client1)  
* startIndex = Pagination - The 1-based index of the first result in the current set of search results  
* count = Pagination - Number of elements to be returned in the current set of search results  
* callback(error, ret):  
error = null if OK, else error object  
ret.Resources = array filled with objects containing userName and id (userName and id set to the same value) e.g [{"userName":"bjensen","id":"bjensen"}, "userName":"jsmith","id":"jsmith"}]  
ret.totalResults = if supporting pagination attribute should be set to the total numbers of elements (users) at the endpoint else set to null

### exploreGroups  

	scimgateway.on('exploreGroups', function (baseEntity, startIndex, count, callback) {
	    var ret = {
	        "Resources": [],
	        "totalResults": null
	    }
		...
		callback(error, ret);
	})  

* callback(error, ret):  
error = null if OK, else error object  
ret.Resources = array filled with objects containing group displayName and id (displayName and id set to the same value) e.g [{"displayName":"Admins","id":"Admins"}, "displayName":"Employees","id":"Employees"}]  
ret.totalResults = if supporting pagination attribute should be set to the total numbers of elements (groups) at the endpoint else set to null

### getUser  

	scimgateway.on('getUser', function (baseEntity, userName, attributes, callback) {
		...
		callback(error, userObj)
	})  

* userName = user id (eg. bjensen)  
* attributes = scim attributes to be returned in callback. If no attributes defined, all should will be returned.  
* callback(error, userObj): userObj containing scim userattributes/values
eg:  
{"id":"bjensen","name":{"formatted":"Ms. Barbara J Jensen III","familyName":"Jensen","givenName":"Barbara"}}

Note, CA Provisioning use two types of "getUser"  
1. Check if user exist: attributes=userName and/or id  
2. Retrive user: attributes=list of all attributes

### createUser

	scimgateway.on('createUser', function (baseEntity, userObj, callback) {
		...
		callback(error)
	}) 

* userObj = user object containing userattributes according to scim standard  
Note, multi-value attributes excluding user attribute 'groups' are customized from array to object based on type  
* callback(error): null if OK, else error object  

### deleteUser  

	scimgateway.on('deleteUser', function (baseEntity, id, callback) {
		...
		callback(error)
	}) 

* id = user id to be deleted 
* callback(error): null if OK, else error object  

### modifyUser  

	scimgateway.on('modifyUser', function (baseEntity, id, attrObj, callback) {
		...
		callback(error)
	}) 


* id = user id  
* attrObj = object containing userattributes to be modified according to scim standard  
Note, multi-value attributes excluding user attribute 'groups' are customized from array to object based on type  
* callback(error): null if OK, else error object 

### getGroup  

	scimgateway.on('getGroup', function (baseEntity, displayName, attributes, callback) {
		...
		callback(error, retObj)
	}) 


* displayName = group name  
* attributes  = scim attributes to be returned in callback (displayName and members is mandatory)  
* callback(error, retObj): retObj containing group displayName and id (+ members if using default "users are member of group")  

	eg. using default "users are member of group":  
{"displayName":"Admins","id":"Admins","members":[{"value":"bjensen","display":"bjensen"]}  

	eg. using "groups are member of user":  
{"displayName":"Admins","id":"Admins"}

	If we do not support groups, callback(null, null)

### getGroupMembers  

	scimgateway.on('getGroupMembers', function (baseEntity, id, attributes, callback) {
	    let arrRet = []
		...
		callback(error, arrRet)
	})

Retrieve all users for a spesific group WHEN **"user member of group"**. This setting is CA IM default scim endpoint configuration. This means Group having multivalue attribute members containing userName.  

* id = user id (eg. bjensen)  
* attributes = attributes to be returned in callback (we only return the name of groups - displayName and current user as member)  
* startIndex = Pagination - The 1-based index of the first result in the current set of search results  
* count = Pagination - Number of elements to be returned in the current set of search results  
* callback(error, ret):  
ret.Resources = array to be filled with objects containing groups with current user as member  
e.g [{"displayName":"Admins","members": [{ "value": bjensen}]}, {"displayName":"Employees", "members": [{ "value": bjensen}]}]  

	ret.totalResults = if supporting pagination attribute should be set to the total numbers of elements (group members) at the endpoint else set to null  
  
	If we do not support groups (or "user member of group"), callback(null, [])  


### getGroupUsers  

	scimgateway.on('getGroupUsers', function (baseEntity, groupName, attributes, callback) {
    	let arrRet = []
		...
    	callback(error, arrRet)
	})

Retrieve all users for a spesific group WHEN **"group member of user"**. This means user having multivalue attribute groups containing value GroupName  

* groupName = group name (eg. UserGroup-1)  
* attributes = scim attributes to be returned in callback  
* callback(error, arrRet): arrRet = array containing the userName's'
	eg: [{"userName", "bjensen"}, {"userName", "jsmith"}]

	If we do not support groups (or "group member of user"), callback(null, [])  

### createGroup  
	scimgateway.on('createGroup', function (baseEntity, groupObj, callback) {
		...
	    return callback(error)
	})

* groupObj = group object containing groupattributes according to scim standard  
groupObj.displayName contains the group name to be created
* callback(error): null if OK, else error object  


### modifyGroupMembers  

	scimgateway.on('modifyGroupMembers', function (baseEntity, id, members, callback) {
		...
	    return callback(error)
	})

* id = group name (eg. Admins)  
* members = array of objects containing groupmembers modifications  
eg: {"value":"bjensen"},{"operation":"delete","value":"jsmith"}  
(adding bjensen and deliting jsmith from group)  
* callback(error): null if OK, else error object  
If we do not support groups, callback(null)









## Known limitations  

* Installation gives error messages related to the module soap optional dependency to 'ursa' that also includes 'node-gyp'. These error messages can be ignored unless soap WSSecurityCert functionality is needed in custom plugin code.  

* Importing "certificate authority - CA" on the CA Connector Server gives a "Failure" message. Restarting connector shows certificate have been installed and HTTPS communication works fine.  

* Using HTTPS seems to slow down the CA Provisioning - ScimGateway communication. Example: Using Provisioning Manager UI and retrieving an account takes approx. 0.5 sec with HTTP, but same operation with HTTPS takes approx. 1.5 sec. (tested both self-signed and Active Directory signed certificate). 

* Delete groups not supported  


## License  
 
MIT © [Jarle Elshaug](https://www.elshaug.xyz)


## Change log  

### v1.0.3  
[Fix]  

- Undefined root url not handled correctly after v1.0.0

### v1.0.2  
[Fix]  

- License and group defined as capability attributes in metafile used by CA ConnectorXpress regarding plugin-azure-ad     

### v1.0.1  
[FIX]  

- Mocha test script did not terminate after upgrading from 3.x to 4.x of Mocha  

### v1.0.0  
[ENHANCEMENT]  

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
[ENHANCEMENT]  

- Includes api gateway for general none provisioning  
  - GET /api
  - GET /api?queries
  - GET /api/{id}
  - POST /api + body
  - PUT /api/{id} + body
  - PATCH /api/{id} + body
  - DELETE /api/{id}
- plugin-api.js demonstrates api functionallity (becomes what you want it to become) 


### v0.5.2  
[ENHANCEMENT]  

- One or more of following authentication/authorization methods are supported:  
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
[ENHANCEMENT]  

- Document updated on how to run ScimGateway as a Docker container  
- `config\docker` includes docker configuration examples  
**Thanks to Charley Watson and Jeffrey Gilbert**  


### v0.4.5  
[ENHANCEMENT]  

- Environment variable `SEED` overrides default password seeding  
- Setting ScimGateway port to `"process.env.XXX"` lets environment variable XXX define the port  
- Don't validate config-file port number for numeric value (Azure AD - iisnode using a name pipe for communication) 

**[UPGRADE]**  

- Configuration files for custom plugins `config/plugin-xxx.json` needs to be updated:  
	- Encrypted passwords needs to be reset to clear text passwords
	- Start ScimGateway and passwords will become encrypted  

### v0.4.4  
[ENHANCEMENT]  

- NoSQL Document-Oriented Database plugin: `plugin-loki`  
This plugin now replace previous `plugin-testmode`  
**Thanks to Jeffrey Gilbert**  
- Minor code/comment reorganizations in provided plugins  
- Minor adjustments to multi-value logic introduced in v0.4.0  

**[UPGRADE]**  

- Delete depricated `lib/plugin-testmode.js` and `config/plugin-testmode.json`
- Edit index.js, replace tesmode with loki   

### v0.4.2
[Fix]  

- plugin-restful minor adjustments to multivalue and cleared attributes logic introduced in v0.4.0  

### v0.4.1
[ENHANCEMENT]  

- Mocha test scripts for automated testing of plugin-testmode  
- Automated tests run on Travis-ci.org (click on build badge) 
- **Thanks to Jeffrey Gilbert**
  
[Fix]  

- Minor adjustments to multi-value logic introduced in v0.4.0

### v0.4.0  
[ENHANCEMENT]  

- Not using the SCIM standard for handling multivalue attributes and cleared attributes. Changed from array to object based on type. This simplifies plugin-coding for multivalue attributes like emails, phoneNumbers, entitlements, ...
- Module dependencies updated to latest versions  

**[UPGRADE]**  

- Custom plugins using multivalue attributes needs to be updated regarding methods createUser and modifyUser. Please see example plugins for details.

### v0.3.8  
[Fix]  

- Minor changes related to SCIM specification

### v0.3.7  
[ENHANCEMENT]  

- PFX / PKCS#12 certificate bundle is supported

### v0.3.6  
[ENHANCEMENT]  

- ScimGateway used by Microsoft Azure Active Directory is supported
- SCIM version 2.0 is supported
- Create group is supported  

**[UPGRADE]**  

- For custom plugins to support create group, they needs to be updated regarding listener method `scimgateway.on('createGroup',...` Please see example plugins for details. 



### v0.3.5  
[Fix]  

- plugin-mssql not included in postinstall  

### v0.3.4  
[ENHANCEMENT]  

- MSSQL example plugin: `plugin-mssql` 
- Changed multivalue logic in example plugins, now using `scimgateway.getArrayObject`  

[Fix]  

- Minor changes related to SCIM specification


### v0.3.3  
[Fix]  

- Logic for handling incorrect pagination request to avoid endless loop conditions (there is a pagination bug in CA Identity Manager v.14)  
- Pagination now supported on getGroupMembers  

**[UPGRADE]**  

- Custom plugins needs to be updated regarding listener method `scimgateway.on('getGroupMembers',...` New arguments have been added "startIndex" and "count". Also a new return variable "ret". Please see example plugins for details.

### v0.3.2  
[Fix]  

- Minor changes related to SCIM specification

### v0.3.1  
[ENHANCEMENT]  

- REST Webservices example plugin: `plugin-restful` 

### v0.3.0  
[ENHANCEMENT]  

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
[Fix]

- plugin-forwardinc explore of empty endpoint

### v0.2.0  
Initial version


