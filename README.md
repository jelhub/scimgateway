
# ScimGateway  

[![npm Version](https://img.shields.io/npm/v/scimgateway.svg?style=flat-square&label=latest)](https://www.npmjs.com/package/scimgateway)[![npm Downloads](https://img.shields.io/npm/dt/scimgateway.svg?style=flat-square)](https://www.npmjs.com/package/scimgateway) [![chat disqus](https://jelhub.github.io/images/chat.svg)](https://elshaug.xyz/md/scimgateway#disqus_thread) [![GitHub forks](https://img.shields.io/github/forks/jelhub/scimgateway.svg?style=social&label=Fork)](https://github.com/jelhub/scimgateway)  

---  
Author: Jarle Elshaug  

Validated on:  

- CA Identity Manager
- Microsoft Azure Active Directory (Early Stage Code)

## Overview  
 
With ScimGateway we could do user management by using REST based [SCIM](http://www.simplecloud.info/) protocol, and the gateway will translate and communicate towards destinations using endpoint specific protocols.  

ScimGateway is a standalone product, however this document shows how the gateway could be used by products like CA Identity Manager.

Using CA Identity Manager, we could setup one or more endpoints of type SCIM pointing to the gateway. Specific ports could then be used for each type of endpoint, and the ScimGateway would work like a "CA Connector Server" communicating with endpoints.

![](https://jelhub.github.io/images/ScimGateway.svg)

Instead of using IM-SDK for building our own integration for none supported endpoints, we can now build new integration based on ScimGateway plugins. ScimGateway works with IM as long as IM supports SCIM.

ScimGateway is based on the popular asynchronous event driven framework [Node.js](https://nodejs.org/en/about/) using javascripts. It is firewall friendly using REST webservices. Runs on almost all operating systems, and may loadbalance between hosts (horizontal) and cpu's (vertical). Could even be uploaded and run as a cloud application.

Following example plugins are included:

* **Testmode** (SCIM)  
SCIM endpoint simulation (in-memory, no physical endpoint)  
Two predefined users  
Supports explore, create, delete, modify and list users (including groups)  
Example of a fully functional ScimGateway plugin  

* **RESTful** (REST Webservice)  
REST plugin using "Testmode" as a REST endpoint

* **Forwardinc** (SOAP Webservice)  
Endpoint that comes with CA IM SDK (SDKWS) for testing SOAP Webservice user-provisioning (please see [wiki.ca.com](https://docops.ca.com/ca-identity-manager/12-6-8/EN/programming/connector-programming-reference/sdk-sample-connectors/sdkws-sdk-web-services-connector/sdkws-sample-connector-build-requirements "wiki.ca.com"))  
Using WS-Security    
Shows how to use custom SOAP header with signed SAML assertion for authentication or token request towards a Security Token Service   
Shows how to implement a higly configurable multi tenant or multi endpoint solution using "baseEntity" parameter  

* **MSSQL** (MSSQL Database)  
Using SQL for userprovisioning towards MSSQL database table

* **SAP HANA** (SAP HANA Database)  
SAP HANA specific user provisioning



## Installation  

#### Install Node.js  

Node.js is a prerequisite and have to be installed on the server.  

[Download](https://nodejs.org/en/download/) the windows installer (.msi 64-bit) and install using default options.  

#### Install ScimGateway  

Open a command window (run as administrator)  
Create a directory for installation e.g. C:\CA\scimgateway and install in this directory

	cd C:\CA\scimgateway
	npm install scimgateway

Please **ignore any error messages** unless soap WSSecurityCert functionality is needed in your custom plugin code. Module soap installation of optional dependency 'ursa' that also includes 'node-gyp' then needs misc. prerequisites to bee manually be installed.


**C:\\CA\\scimgateway** will now be `<package-root>` 
 
index.js, lib and config directories containing example plugins have been copied from the original scimgateway package located under node_modules.  

If internet connection is blocked, we could install on another machine and copy the scimgateway folder.


#### Startup and verify default testmode-plugin 

	node C:\CA\scimgateway
	
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

	cd C:\CA\scimgateway
	npm outdated

Lists current, wanted and latest version. No output on screen means we are running the latest version.

Upgrade to latest version:  

	cd C:\CA\scimgateway
	npm update scimgateway

>Note, always backup/copy C:\\CA\\scimgateway before update/install. Custom plugins and corresponding configuration files will not be affected.  

## Configuration  

**index.js** defines one or more plugins to be started. We could comment out those we do not need (default configuration only starts testmode plugin).  

	var testmode    = require('./lib/plugin-testmode');
	// var restful  = require('./lib/plugin-restful');
	// var forwardinc  = require('./lib/plugin-forwardinc');
	// var mssql = require('./lib/plugin-mssql');
	// var saphana   = require('./lib/plugin-saphana');

  

Each endpoint plugin needs a javascript file (.js) and a configuration file (.json). **They both must have the same naming suffix**. For SAP Hana endpoint we have:  
>lib\plugin-saphana.js  
>config\plugin-saphana.json


Edit specific plugin configuration file according to your needs.  
Below shows an example of config\plugin-saphana.json  
  
	{
		"scimgateway": {
			"scimversion": "1.1",
	        "loglevel": "error",
	        "localhostonly": false,
	        "port": 8884,
	        "username": "gwadmin",
	        "password": "password",
			"oauth": {
            	"accesstoken": null
        	},
	        "certificate": {
	            "key": null,
	            "cert": null,
	            "ca": null
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

- **scimversion** - "1.1" or "2.0". Default is "1.1". For Azure AD "2.0" should be used.  

- **loglevel** - error or debug. Output to console and logfile `logs\plugin-saphana.log` (debug not sent to console)  

- **localhostonly** - true or false. False means gateway accepts incoming requests from all clients. True means traffic from only localhost (127.0.0.1) is accepted (gateway must then be installed on the Provisioning Server).  

- **port** - Gateway will listen on this port number. Clients (e.g. Provisioning Server) will be using this port number for communicating with the gateway. For endpoint the port is the port number used by plugin for communicating with SAP Hana 

- **username** - username used by clients for gateway authentication. For endpoint the username refers to endpoint authentication.  

- **password** - password used by clients for gateway authentication. For endpoint the password refers to endpoint authentication. Note, we set a clear text password and when gateway is started this **password will become encrypted and updated in the configuration file**.  

- **oauth** - For Azure AD, define access token for OAuth2 bearer token (access token). This will be the password accepted by ScimGateway. Using standard OAuth key/secret/endpoints is not supported.  

- **certificate** - If not using SSL/TLS certificate, set "key", "cert" and "ca" to **null**. When using SSL/TLS, "key" and "cert" have to be defined with the filename corresponding to the primary-key and public-key. Both files must be located in the `<package-root>\config\certs` directory e.g:  
  
		"certificate": {
			"key": "key.pem",
			"cert": "cert.pem",
			"ca": null
		}

  Example of how to make a self signed certificate:  
  `openssl req -nodes -newkey rsa:2048 -x509 -sha256 -days 3650 -keyout key.pem -out cert.pem -subj "/O=Testing/OU=ScimGateway/CN=<FQDN>"`  

  `<FQDN>` is Fully Qualified Domain Name of the host having ScimGateway installed
  
  Note, when using CA Provisioning, the "certificate authority - CA" also have to be imported on the Connector Server. For self-signed certificate CA and the certificate (public key) is the same.

- **samlprovider** - SAP Hana specific saml provider name. Users created in SAP Hana needs to have a saml provider defined.

## Manual startup    

Gateway can now be started from a command window running in administrative mode

3 ways to start:

	node C:\CA\scimgateway

	node C:\CA\scimgateway\index.js

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
	Program/script = C:\Program Files\nodejs\node.exe
	Arguments = C:\CA\scimgateway

	Settings - tab:
	---------------
	Stop the task if runs longer than = Disabled (greyed out)

Verification:

- Right click task - **Run**, verify process node.exe (ScimGateway) can be found in the task manager (not the same as task scheduler). Also verify logfiles `<pakage-root>\logs`  
- Right click task - **End**, verify process node.exe have been terminated and disappeared from task manager   
- **Reboot** server and verify ScimGateway have been automatically started

## CA Provisioningserver - SCIM Endpoint  

Using the CA Provisioning Manager we have to configure  
  
`Endpoint type = SCIM (DYN Endpoint)`  

SCIM endpoint configuration example for Testmode plugin (plugin-testmode)

	Endpoint Name = Testmode  
	User Name = gwadmin  
	Password = password  
	SCIM Authentication Method = HTTP Basic Authentication  
	SCIM Based URL = http://localhost:8880  

	or:  

	SCIM Based URL = http://localhost:8880/[baseEntity]

Username, password and port must correspond with plugin configuration file. For "Testmode" plugin it will be `config\plugin-testmode.json`  

"SCIM Based URL" refer to the FQDN (or localhost) having ScimGateway installed. Portnumber must be included. Use HTTPS instead of HTTP if ScimGateway-configuration includes certificates. 

"baseEntity" is optional. This is a parameter used for multi tenant or multi endpoint solutions. We could create several endpoints having same base url with unique baseEntity. e.g:  

http://localhost:8880/clientA  
http://localhost:8880/clientB

Each baseEntity should then be defined in the plugin configuration file with custom attributes needed. Please see examples in plugin-forwardinc.

IM 12.6 SP7 (and above) also supports pagination for SCIM endpoint (data transferred in bulks - endpoint explore of users). Testmode plugin supports pagination. Other plugin may ignore this setting.  

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

## SAP Hana endpointspecific details  

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

Only SAML users will be explored and managed

Supported template attributes:  

- User Name (UserID)
- Suspended (Enabled/Disabled)  

Currently no other attributes needed. Trying to update other attributes will then give an error message.  **The SCIM Provisioning template should therefore not include any other global user attribute references.**

SAP Hana converts UserID to uppercase. Provisioning use default lowercase. Provisioning template should therefore also convert to uppercase.

	User Name = %$$TOUPPER(%AC%)%

## Microsoft Azure Active Directory  
"Early Stage Code"  

Azure AD first checks if user/group exists, if not exist they will be created.  

Deleting a user i Azure AD sends a modify user `{"active":"False"}` which means user should be disabled. Standard SCIM "DELETE" method is not used?  

Plugin configuration file must include:

	"scimversion": "2.0",
    "oauth": {
        "accesstoken": "<password>"
    },

Access token password must correspond with "Secret Token" defined in Azure AD

`Azure-Azure Active Directory-Enterprise Application-<My Application>-Provisioning-Secret Token`

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

 
## How to build your own plugins  
For javascript coding editor you may use [Visual Studio Code](https://code.visualstudio.com/ "Visual Studio Code") 

Preparation:

* Copy `lib\plugin-testmode.js` and `config\plugin-testmode.json` and rename both copies to your plugin name prefix e.g. plugin-mine.js and plugin-mine.json (for SOAP Webservice endpoint we might use plugin-forwardinc as a template) 
* Edit plugin-mine.json and define a unique port number for the scimgateway setting  
* Edit index.js and add a new line for starting your plugin e.g. `var mine = require('./lib/plugin-mine');`  
* Start ScimGateway and verify. If using CA Provisioning you could setup a SCIM endpoint using the port number you defined  

Now we are ready for custom coding by editing plugin-mine.js
Coding should be done step by step and each step should be verified and tested before starting the next (they are all highlighted by comments in existing code).  

1. **Turn off group functionality** in getGroup, getGroupMembers, getGroupUsers and modifyGroupMembers  
Please see callback definitions in plugin-saphana that do not use groups.
2. **explore users** (test provisioning explore users)
3. **get user** (test provisioning retrieve account)
4. **create user** (test provisioning new account)
5. **delete user** (test provisioning delete account)
6. **modify user** (test provisioning modify account)
7. **explore groups** (test provisioning explore groups)
8. **Turn on group functionality** (if supporting groups)
8. **get group** (test provisioning group list groups)
9. **get group members** (test provisioning retrieve account - group list groups)
10. **modify group members** (test provisioning retrieve account - group add/remove groups)
11. **get group users** (if using "groups member of user")    

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

## Known limitations  

* Installation gives error messages related to the module soap optional dependency to 'ursa' that also includes 'node-gyp'. These error messages can be ingnored unless soap WSSecurityCert functionality is needed in custom plugin code.  

* Importing "certificate authority - CA" on the CA Connector Server gives a "Failure" message. Restarting connector shows certificate have been installed and HTTPS communication works fine.  

* Using HTTPS seems to slow down the CA Provisioning - ScimGateway communication. Example: Using Provisioning Manager UI and retrieving an account takes approx. 0.5 sec with HTTP, but same operation with HTTPS takes approx. 1.5 sec. (tested both self-signed and Active Directory signed certificate). 

* Delete groups not supported  


## License  

MIT


## Change log  

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

- Minor changes related to SCIM 1.1


### v0.3.3  
[Fix]  

- Logic for handling incorrect pagination request to avoid endless loop conditions (there is a pagination bug in CA Identity Manager v.14)  
- Pagination now supported on getGroupMembers  

**[UPGRADE]**  

- Custom plugins needs to be updated regarding listener method `scimgateway.on('getGroupMembers',...` New arguments have been added "startIndex" and "count". Also a new return variable "ret". Please see example plugins for details.

### v0.3.2  
[Fix]  

- Minor changes related to SCIM 1.1

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


