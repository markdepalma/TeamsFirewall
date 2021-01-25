# TeamsFirewall
The open-source ethical firewall for Microsoft Teams built on [mitmproxy](https://github.com/mitmproxy/mitmproxy) and written in Python.

TeamsFirewall sits in between the Teams client and the Teams service learning the environment by creating a cache of the users/conversations it observes without requiring any access to the tenant. This deep context (**user -> conversation -> event**) gives you the ability to create extremely granular rules for your Teams environment. You can create a rule so broad that it blocks all external communication or very specific rule that prevents message edits between user A and user B.

Please refer to the [TODO](https://github.com/markdepalma/TeamsFirewall/blob/main/TODO.md) for upcoming features.

### Prerequisites
 - Windows/Linux environment
 - [MITMProxy](https://github.com/mitmproxy/mitmproxy)

### Install
 - [Install mitmproxy](https://docs.mitmproxy.org/stable/overview-installation/)
 - Place **teamsfirewall.py** in a directory
 - Create teamsfirewall.config and place in same directory
 - Execute mitmproxy (ex. **mitmweb.exe --no-web-open-browser --scripts "teamsfirewall.py"**)
 - Configure clients to trust the [mitmproxy certificate](https://docs.mitmproxy.org/stable/concepts-certificates/)
 - Configure clients to use TeamsFirewall as a proxy. Currently, the best way to do this is with a PAC file as **only a subset Teams traffic needs to pass through TeamsFirewall**. An example PAC file has been included

### Configuration
TeamsFirewall is configured with a single XML configuration file (teamsfirewall.config) . The configuration file is comprised of various firewall settings and also includes rules. TeamsFirewall has a built-in rule engine that is made up **conditions** and **actions**. Each rule can have one or more conditions and actions. All conditions have an implicit AND between them. An example configuration file is included in the repository.

#### General Settings
 - **Internal tenant ID(s)**
	 - Possible values: Azure AD tenant ID(s)
	 - Description: One or more tenant IDs that are part of your internal environment. This used for determining the "location" of events during rule evaluation
	 - Example: `<InternalTenantIds><TenantId>*TENANT ID*</TenantId></InternalTenantIds>`  OR   `<InternalTenantIds><TenantId>*TENANT ID 1*</TenantId><TenantId>*TENANT ID 2*</TenantId></InternalTenantIds>`
 - **Add X-Forwarded-For header**
	 - Possible values: TRUE OR FALSE
	 - Example: `<AddXFFHeader>TRUE</AddXFFHeader>`
	 - Description: Add a **X-Forwarded-For** header containing the client's IP address to outgoing firewall traffic. This is useful for supporting user-based decisions in downstream firewalls
 - **API token purge interval**
	 - Possible values: Numerical value in minutes
	 - Description: The interval at which the firewall will purge expired user API tokens from the cache database. This is evaluated during token save events
	 - Example: `<APITokenPurgeInterval>240</APITokenPurgeInterval>`
 - **Conversation map lifetime**
	 - Possible values: Numerical value in minutes
	 - Description: The amount of minutes a cached conversation (particularly the participant list) is considered valid in the cache. After this time has elapsed the firewall will send a request for updated conversation information. Too high of a value may result in the firewall not picking up on conversation participant member changes. Too low of a value will result in more frequent conversation lookups and reduced firewall performance
	 - Example: `<ConversationMapLifetime>10</ConversationMapLifetime>`
 - **User lifetime**
	 - Possible values: Numerical value in minutes
	 - Description: The amount of minutes a cached user is considered valid in the cache. After this time has elapsed the firewall will send a request for updated conversation information. User changes are normally only encountered when a primary email address is changed or a user is deleted/recreated. Too low of a value will result in more user lookups which can be taxing in situations where the participant list is large
	 - Example: `<UserLifetime>300</UserLifetime>`
 - **Max API user lookup threads**
	 - Possible values: Numerical value
	 - Description: The number of threads used for user lookups (when needed) during a conversation look up
	 - Example: `<MaxAPIUserLookupThreads>30</MaxAPIUserLookupThreads>`
 - **Log levels**
	 - Possible values: INFO or DEBUG
	 - Description: The log levels for the various components in TeamsFirewall. Logging is currently sent to both the console and the "**teamsfirewall.log**" log file which is located in the same directory. Log files have a maximum size of 400KB with an automatic 20 log rotation
	 - Example: 
	  `<LogLevels>
	<CORE>DEBUG</CORE>
	<RULEEVAL>INFO</RULEEVAL>
	<APITOKENMGMT>INFO</APITOKENMGMT>
	<GETTEAMSUSER>INFO</GETTEAMSUSER>
	<GETCONVERSATION>INFO</GETCONVERSATION> </LogLevels>
`

#### Rule Conditions
 - **Event**
	 - Type: EVENT
	 - Value: Comma-delimited list of event codes
	 - Possible values
		 - MSGTYP
			 - A message typing notification
		 - MSGSND
			 - Message send
		 - MSGDEL
			 - Message delete
		 - MSGUDEL
			 - Message un-delete
		 - MSGEMO
			 - Message reaction/emoji (and removal of)
		 - MSGEDIT
			 - Message edit
 - **Conversation type**
	 - Type: CONVERSATIONTYPE
	 - Value: Comma-delimited list of conversation type codes
	 - Possible values
		 - DIRECTCHAT
			 - A 1:1 (direct) chat
		 - GROUPCHAT
			 - A 1:n (group) chat
		 - TEAMCHATSTD
			 - A standard team channel
		 - TEAMCHATPRIV
			 - A private team channel
		 - MEETINGCHAT
			 - A meeting
 - **Location**
	 - Type: LOCATION
	 - Value: Internal or external location
	 - Possible values
		 - INTERNAL
			 - Action took place within an internal tenant
		 - EXTERNAL
			 - Action took place in an external tenant (ex. guest account in another tenant)
 - **Federated**
	 - Type: FEDERATED
	 - Value: True or false
	 - Possible values
		 - TRUE
			 - A participant (recipient) in the action is an external user (the user will usually have "External" next to their name)
		 - FALSE
			 - All participants are non-external
 - **Actors**
	 - Type: ACTORS
	 - Value: Comma-delimited list of possible actors. Wildcards are also supported here. Actors are defined as the user who performed the action
	 - Possible values
		 - *@consoto.com
		 - bill@consoto.com
		 - bill@consoto.com,ruth@companyb.com
		 - bill@consoto.com,ruth@companyb.com,*@companyc.com
 - **Participants**
	 - Type: PARTICIPANTS
	 - Value: Comma-delimited list of possible participants. Wildcards are also supported here. Participants are defined ever user other than actor
	 - Possible values
		 - *@consoto.com
		 - bill@consoto.com
		 - bill@consoto.com,ruth@companyb.com
		 - bill@consoto.com,ruth@companyb.com,*@companyc.com

#### Rule Actions
 - **Block**
	 - Description: The action will be blocked via a HTTP 400 response
	 - Type: BLOCK
	 - Param1: N/A
	 - Param2: N/A
 - **Log**
	 - Description: The action will be logged. This will be logged to the firewall's log file
	 - Type: LOG
	 - Param1: The text to be logged
	 - Param2: N/A
 - **Add header**
	 - Description: Add an HTTP header to the action. This is useful for taking action on the action downstream (ex. at a network firewall)
	 - Type: ADDHEADER
	 - Param1: Header name
	 - Param2: Header value
