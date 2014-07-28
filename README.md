#LATCH INSTALLATION GUIDE FOR OpenLDAP

## INTRODUCTION ##
- The module for OpenLDAP allows to integrate Latch into any  LDAP directory based on OpenLDAP 2.4. Implemented as an OpenLDAP’s overlay, it is possible to associate the module to any database supported by OpenLDAP (bdb, hdb, ldif, ldap, etc) and to intercept successful answers to received BIND requests. This adds the chance to check of a certain latch before answering to the client. If the latch is closed, the module will modify the response to the BIND request and the client will receive an invalid credentials error.

- To be able to determine the latch that must be checked in each request, the module will connect to a second LDAP directory. In this directory, it will look for an entry depending on the original BIND request. From its configuration parameters , it will recover a certain attribute.

- Configuring an OpenLDAP in proxy mode (with a LDAP database) and using this module, makes it possible to incorporate Latch into any LDAP directory.



##INSTALLING THE LATCH MODULE
- This module is ready to be used in Linux. It has been successfully tested in Debian 7 of 64 bits and Ubuntu 13 of 64 bits too.

- The examples of code showed here have been executed in Debian 7, commands used are for this Linux’s version. It should work under other versions, following the same steps, but using equivalent commands.


###PREREQUISITES 
#### Compiling requirements  ####
-    Tools *gcc* and *make*.

-	OpenLDAP 2.4.39 sources installed, configured and built.

-	The headers and the shared libraries from PCRE, JSON-C, OpenSSL y cURL.

#### Installation requirements ####
-	In addition to OpenLDAP, the database to which you want to associate the module must also be configured.

-	The shared libraries from PCRE, JSON-C, OpenSSL y cURL.

-  To get the **"Application ID"** and **"Secret"**, (fundamental values for integrating Latch in any application), it’s necessary to register a developer account in [Latch's website](https://latch.elevenpaths.com). On the upper right side, click on **"Developer area"**. 


###DOWNLOADING THE MODULE
 * When the account is activated, the user will be able to create applications with Latch and access to developer documentation, including existing SDKs and plugins. The user has to access again to [Developer area](https://latch.elevenpaths.com/www/developerArea), and browse his applications from **"My applications"** section in the side menu.

* When creating an application, two fundamental fields are shown: **"Application ID"** and **"Secret"**, keep these for later use. There are some additional parameters to be chosen, as the application icon (that will be shown in Latch) and whether the application will support OTP  (One Time Password) or not.

* From the side menu in developers area, the user can access the **"Documentation & SDKs"** section. Inside it, there is a **"SDKs and Plugins"** menu. Links to different SDKs in different programming languages and plugins developed so far, are shown.

###INSTALLING THE MODULE
#### Compiling the module ####
Compiling the module requires some previous steps:

- The user will need to have installed, configured and built the sources of an OpenLDAP 2.4.39, which may require the installation of additional packages to be able to configure and build those sources.


	1.Install required packages:

    	root@debian:~# apt-get install file
	    root@debian:~# apt-get install libtool
    	root@debian:~# apt-get install libicu-dev
	    root@debian:~# apt-get install libssl-dev
    	root@debian:~# apt-get install libsasl2-dev




	2.Download the sources of an OpenLDAP 2.4.39 and extract them to a directory:
	    
		user@debian:~$ mkdir -p workspace/openldap
		user@debian:~$ cd workspace/openldap
		user@debian:~/workspace/openldap$ wget ftp://ftp.openldap.org/pub/OpenLDAP/openldap-release/openldap-2.4.39.tgz
		user@debian:~/workspace/openldap$ tar zxvf openldap-2.4.39.tgz
		user@debian:~/workspace/openldap$ cd openldap-2.4.39
		user@debian:~/workspace/openldap/openldap-2.4.39$ mkdir dist
	
	
	
	3.Run the configure tool:
	
		user@debian:~/workspace/openldap/openldap-2.4.39$ ./configure --prefix=`pwd`/dist --enable-dynamic=yes --enable-slapd --enable-modules=yes --enable-backends=no --enable-overlays=no
		
	(The command **pwd** returns the current directory).
	
	
	4.Build the package:
		
		user@debian:~/workspace/openldap/openldap-2.4.39$ make


- Headers and shared libraries listed in the prerequisites must be installed:

    	root@debian:~# apt-get install libssl-dev
    	root@debian:~# apt-get install libcurl4-openssl-dev
    	root@debian:~# apt-get install libjson0-dev
    	root@debian:~# apt-get install libpcre3-dev

After these steps, the module is ready to be compiled.
To build the overlay, the first step is to export the environment variable OPENLDAP_DIR to make it point to the directory where the sources of an OpenLDAP 2.4.39 are installed, configured and built.

    user@debian:~$ export OPENLDAP_DIR=${HOME}/workspace/openldap/openldap-2.4.39

Download the module sources to a local folder of the server, with a git clone command or with any other method (as copying the files from other server).

For the following commands, the module sources are located in the directory:

    ${HOME}/workspace/11paths/path2-sdk/Plugins/LDAP/Proxy.

The next step is just to execute **make** from the directory where the overlay's sources are. It's recommended to execute **make clean** before to be sure that all the objects are built from scratch:
 
    user@debian:~/workspace/11paths/path2-sdk/Plugins/LDAP/Proxy$ make clean
    user@debian:~/workspace/11paths/path2-sdk/Plugins/LDAP/Proxy$ make

In the **dist/lib** directory there must be a shared library named **latch-overlay.so**. This library is the overlay and we will have to install it in those servers where it will be used.


#### Installing the module in OpenLDAP ####
The overlay depends on some shared libraries (listed in the prerequisites):

    root@debian:~# apt-get install libssl1.0.0
    root@debian:~# apt-get install libcurl3
    root@debian:~# apt-get install libjson0
    root@debian:~# apt-get install libpcre3

We can verify that all the dependencies are resolved through the **ldd** utility, as it will allow us to check that all the shared libraries are found correctly. For example, if some dependency is not satisfied when executing:

    root@debian:~/workspace/11paths/path2-sdk/Plugins/LDAP/Proxy/dist/lib# ldd latch-overlay.so

the standard output will show something like this:

    libjson.so.0 => not found

If everything is ok, the first step is to copy the shared library to a directory in the server. The simplest way is to copy it to the **/usr/lib/ldap** directory, where the official OpenLDAP backends and overlays are installed.

Once this has been done, configure the OpenLDAP server to load the module adding a value to the **olcModuleLoad** attribute.
 
If we wish to load the module from some other directory different than **/usr/lib/ldap** modify the **olcModulePath** attribute of the **cn=module{0},cn=config** configuration object. 

This attribute must be directly modified in the LDIF file **cn=module{0}.ldif** (which in Debian is in **/etc/ldap/slapd.d/cn=config** folder), as this version of OpenLDAP doesn't allow to modify it through **ldapmodify**.

We have to add the install dir of the overlay to the end of the current value, using the ':' character as separator.

    olcModulePath: /usr/lib/ldap:${INSTALL_DIR}

(${INSTALL_DIR} must be replaced by the path to the folder where the overlay has been installed).

And stop and start the server:

    root@debian:~# /etc/init.d/slapd stop
    root@debian:~# /etc/init.d/slapd start

This will generate a message warning about the integrity of some config files that has been compromised. To avoid this, we may calculate the new checksum with some utility as **cksfv** (removing the first two lines) and update the value of the CRC32 in the modified config file.

It's also posible that we need to modify the **apparmor** config (for example, in Ubuntu) if this product is being used to control the resources the **slapd** binary has access to.

The next step is to attach the overlay to the database where we want to intercept the successful answers to LDAP BIND operations. We will have to create a child object of the database object with the configuration of the overlay. The **application id** and **secret** are added here.


####CONFIGURING THE INSTALLED MODULE
A complete listing of all configuration parameters is provided for reference. The first element of the parameter name is the name of the LDAP attribute associated with the parameter when the on-line configuration (OLC) is being used. The second element in the parameter name is the legacy name of the parameter, just in case the static configuration is still being used. For each parameter in the listing, its description includes if it's required or optional. If a parameter is required but it's not configured, the server will start but each time the overlay tries to check a latch an error message with none level will be sent to the log.

#####MANDATORY PARAMETERS

Parameter name | Legacy name (no recommended) | Description
-- | -- | --
olcLatchApplicationId  | latch-application-id | This parameter defines the application_id the overlay will use in Latch backend calls. It can be obtained from the developer's area of the Latch web site.
olcLatchSecret  | latch-secret | This parameter defines the secret the overlay will use to sign Latch backend calls. It can be obtained from the developer's area of the Latch web site.
olcLatchLDAPURI | latch-ldap-uri | his parameter defines the protocol, server and port of the LDAP server in URL format. For example ldap://127.0.0.1:389
olcLatchLDAPSearchBaseDN | latch-ldap-search-base-dn | This parameter defines the DN that will be used as base in the search operations.
 |  | The string @@@USER@@@ will we replaced by the user's identifier that the overlay has extracted from the DN used in the BIND operation. 
olcLatchLDAPSearchFilter | latch-ldap-search-filter | This parameter defines the search filter that will be used in the search operations. The string @@@USER@@@ will we replaced by the user's identifier that the overlay has extracted from the DN used in the BIND operation.
olcLatchLDAPAttribute | latch-ldap-attribute | This parameter defines the LDAP attribute where the account_id is stored.
olcLatchLDAPTLSCAFile (required if LDAPS) | latch-ldap-tls-ca-file | This parameter defines the file in the system with the trusted CAs in PEM format that will be used to verify the certificate of the LDAPS server.




#####OPTIONAL PARAMETERS

Parameter name | Legacy name (no recommended) | Description
-- | -- | --
olcLatchOperationId | latch-operation-id | This parameter defines the operation_id the overlay will use in Latch backend calls. It can be obtained from the developer's area of the Latch web site. If this parameter is configured, the overlay will ask for the status of the latch associated with this operation_id and not for the status of the latch associated with the application_id (its parent).
olcLatchSDKHost | latch-sdk-host | This parameter defines the protocol, server and port of the Latch backend. The default value, if not specified, is the production backend, located at https://latch.elevenpaths.com.
olcLatchSDKProxy | latch-sdk-proxy | This parameter defines the HTTP/HTTPS proxy to be used in the Latch backend calls.
olcLatchSDKTimeout | latch-sdk-timeout | This parameters defines the timeout for the Latch backend calls. The default value is 2 seconds. 0 means no timeout.
olcLatchSDKCURLNoSignal | latch-sdk-curl-nosignal | This parameter defines if the cURL option CURLOPT_NOSIGNAL should be set to 1. Needed if libcurl < 7.32.0. Disables DNS timeouts.
olcLatchSDKTLSCAFile | latch-sdk-tls-ca-file | This parameter defines the file with trusted CAs in PEM format that will be used to verify the Latch backend certificate. It has priority over olcLatchSDKTLSCAPath. If none of them are set, libcurl default behavior will be used.
olcLatchSDKTLSCAPath | latch-sdk-tls-ca-path | This parameter defines the directory with trusted CAs (see c_rehash) that will be used to verify the Latch backend certificate. olcLatchSDKTLSCAFile has priority over this parameter. If none of them are set, libcurl default behavior will be used.
olcLatchSDKTLSCRLFile | latch-sdk-tls-crl-file | This parameter defines the file with the full chain of CRLs in PEM format (certificate and issuers) that will be used to check if the certificate of the Latch backend or any CA in the chain has been revoked. Must be valid and not expired.
olcLatchExclude | latch-exclude | A multi-valued attribute used to specify a list of regular expressions. If the DN of the object requesting the LDAP BIND operation matches any of these expressions, the overlay won't check any latch.
olcLatchPattern | latch-pattern | This parameter defines the regular expression that will be used to capture the identifier of the user associated with the DN of the object requesting the LDAP BIND operation. Its default value is uid=(.*?),.*
olcLatchLDAPBindDN | latch-ldap-bind-dn | This parameter defines the DN that will be used to authenticate the connections to the LDAP server. If this parameter and the olcLatchLDAPBindPassword are not specified, the connections will be anonymous.
olcLatchLDAPBindPassword | latch-ldap-bind-password | This parameter defines the password that will be used to authenticate the connections to the LDAP server. If this parameter and the olcLatchLDAPBindDN are not specified, the connections will be anonymous.
olcLatchLDAPSearchScope | latch-ldap-search-scope | This parameter defines the search scope that will be used in the search operations. If not specified, the search operations will be done just over the DN specified in the olcLatchLDAPSearchBaseDN parameter (base) but this can be modified configuring this parameter to onelevel (the search operations will be done over the specified DN and its direct children) or subtree (the search operations will be done over the specified DN and all its children).


###UNINSTALLING THE MODULE IN OpenLDAP
Stop the OpenLDAP server and delete the **ldif** file with the overlay configuration.


##RESOURCES
- You can access Latch´s use and installation manuals, together with a list of all available plugins here: [https://latch.elevenpaths.com/www/developers/resources](https://latch.elevenpaths.com/www/developers/resources)

- Further information on de Latch´s API can be found here: [https://latch.elevenpaths.com/www/developers/doc_api](https://latch.elevenpaths.com/www/developers/doc_api)

- For more information about how to use Latch and testing more free features, please refer to the user guide in Spanish and English:
	1. [English version](https://latch.elevenpaths.com/www/public/documents/howToUseLatchNevele_EN.pdf)
	1. [Spanish version](https://latch.elevenpaths.com/www/public/documents/howToUseLatchNevele_ES.pdf)
