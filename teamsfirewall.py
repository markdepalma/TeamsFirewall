import mitmproxy.http
import mitmproxy.ctx
import mitmproxy.utils

import os
import base64
import urllib.parse
import urllib.request
import re
import json
import time
import xml.etree.ElementTree as ET
import sqlite3
import concurrent.futures
import logging
import logging.handlers

class FirewallRule:
	def __init__(self):
		self.name = ''
		self.event = []
		self.conversationtype = []
		self.location = None
		self.isfederated = None
		self.actors = []
		self.participants = []
		self.actions = []

class FirewallRuleAction:
	def __init__(self):
		self.action = ''
		self.param1 = ''
		self.param2 = ''

def get_log_level(level):
	if level == 'DEBUG':
		return 10
	elif level == 'INFO':
		return 20
	else:
		return 0

def load_config():
	#Load config XML
	config_xml_tree = ET.parse(script_dir + '\\teamsfirewall.config')
	config_xml_tree_root = config_xml_tree.getroot()
	
	#Get internal tenant ids
	global config_tenant_ids
	config_tenant_ids = []
	
	for t in config_xml_tree_root.findall('./GeneralSettings/InternalTenantIds/TenantId'):
		config_tenant_ids.append(t.text)
	
	#Get AddXFFHeader setting
	global config_add_xff_header
	if config_xml_tree_root.find('./GeneralSettings/AddXFFHeader').text.upper() == 'TRUE':
		config_add_xff_header = True
	else:
		config_add_xff_header = False
	
	#Get APITokenPurgeInterval setting
	global config_api_token_purge_interval
	config_api_token_purge_interval = int(config_xml_tree_root.find('./GeneralSettings/APITokenPurgeInterval').text) * 60
	
	#Get ConversationMapLifetime setting
	global config_conversation_map_lifetime
	config_conversation_map_lifetime = int(config_xml_tree_root.find('./GeneralSettings/ConversationMapLifetime').text) * 60
	
	#Get UserLifetime setting
	global config_user_lifetime
	config_user_lifetime = int(config_xml_tree_root.find('./GeneralSettings/UserLifetime').text) * 60
	
	#Get MaxAPIUserLookupThreads setting
	global config_max_userlookup_threads
	config_max_userlookup_threads = int(config_xml_tree_root.find('./GeneralSettings/MaxAPIUserLookupThreads').text)
	
	#Get LogLevels
	global config_log_level_core
	global config_log_level_ruleeval
	global config_log_level_apitokenmgmt
	global config_log_level_getteamsuser
	global config_log_level_getconversation
	
	config_log_level_core = get_log_level(config_xml_tree_root.find('./GeneralSettings/LogLevels/CORE').text.upper())
	config_log_level_ruleeval = get_log_level(config_xml_tree_root.find('./GeneralSettings/LogLevels/RULEEVAL').text.upper())
	config_log_level_apitokenmgmt = get_log_level(config_xml_tree_root.find('./GeneralSettings/LogLevels/APITOKENMGMT').text.upper())
	config_log_level_getteamsuser = get_log_level(config_xml_tree_root.find('./GeneralSettings/LogLevels/GETTEAMSUSER').text.upper())
	config_log_level_getconversation = get_log_level(config_xml_tree_root.find('./GeneralSettings/LogLevels/GETCONVERSATION').text.upper())
	
	#Get rules and build rule array
	global config_rules
	config_rules = []
	
	for r in config_xml_tree_root.findall('./Rules/Rule'):
		new_rule = FirewallRule()
		condition_added = True
		action_added = True
		
		new_rule.name = r.find('RuleName').text
		
		#Only add supported conditions
		for c in r.findall('./Conditions/Condition'):
			if c.find('Type').text == 'EVENT':
				new_rule.event = c.find('Value').text.upper().split(',')
			elif c.find('Type').text == 'CONVERSATIONTYPE':
				new_rule.conversationtype = c.find('Value').text.upper().split(',')
			elif c.find('Type').text == 'LOCATION':
				new_rule.location = c.find('Value').text.upper()
			elif c.find('Type').text == 'FEDERATED':
				if c.find('Value').text.upper() == 'TRUE':
					new_rule.isfederated = True
			elif c.find('Type').text == 'ACTORS':
				new_rule.actors = c.find('Value').text.lower().split(',')
			elif c.find('Type').text == 'PARTICIPANTS':
				new_rule.participants = c.find('Value').text.lower().split(',')
			else:
				condition_added = False
		
		#Only add supported actions
		for a in r.findall('./Actions/Action'):
			new_action = FirewallRuleAction()
			
			if a.find('Type').text.upper() == 'DROP':
				new_action.action = 'DROP'
			elif a.find('Type').text.upper() == 'LOG':
				new_action.action = 'LOG'
				new_action.param1 = a.find('Param1').text
			elif a.find('Type').text.upper() == 'ADDHEADER':
				new_action.action = 'ADDHEADER'
				new_action.param1 = a.find('Param1').text
				new_action.param1 = a.find('Param2').text
			else:
				action_added = False
			
			new_rule.actions.append(new_action)
		
		if condition_added == True and action_added == True:
			config_rules.append(new_rule)

def get_json_from_auth_token(auth_header):
	try:
		tokenraw = str(base64.b64decode(auth_header.split('.')[1] + '=='))
		tokenrematch = re.search('{".+("|])}', tokenraw)
		tokenjsonstr = tokenrematch.group(0)
		tokenjson = json.loads(tokenjsonstr)
	except:
		tokenjson = []
	
	return tokenjson

def get_teams_event_code(verb, uri, body):
	verb = verb.upper()
	uri = uri.lower()
	
	event_code = 'OTHER'
	
	if uri.startswith('/v1/users/me/conversations'):
		if verb == 'POST':
			if 'messagetype' in body:
				if '"Control/Typing"' in body:
					event_code = 'MSGTYP'
				else:
					event_code = 'MSGSND'
		elif verb == 'DELETE':
			if body == emptybody:
				event_code = 'MSGDEL'
			elif '"deletetime":null' in body:
				event_code = 'MSGUDEL'
			elif 'properties?name=emotions' in uri:
				#Emotion delete, using same event code currently
				event_code = 'MSGEMO'
		elif verb == 'PUT':
			if 'messagetype' in body:
				event_code = 'MSGEDIT'
			elif '"emotions":' in body:
				event_code = 'MSGEMO'
		elif verb == 'OPTIONS':
			pass
		elif verb == 'GET':
			pass
		else:
			pass
	else:
		pass
	
	return event_code

class TeamsConversation:
	def __init__(self):
		self.type = ''
		self.actor = ''
		self.participants = []
		self.isfederated = False

def purge_expired_api_tokens():
	current_time = int(time.time())
	
	logger_api_token_mgmt.info(f'Purging tokens older than {current_time}')
	
	db_cursor.execute("DELETE FROM authtokens WHERE exp <= ?", (current_time,))
	db_conn.commit()
	
	global api_token_last_purge
	api_token_last_purge = current_time

def save_api_token(token, session, path):
	api_region_regex = '\/api\/\S*\/(\S*)\/(?:v\d|beta)\/'
	
	api_token_json = get_json_from_auth_token(token)
	api_region = re.search(api_region_regex, path, re.IGNORECASE).group(1)
	
	db_cursor.execute("SELECT * FROM authtokens WHERE sessionid = ? AND exp = ?", (session, api_token_json['exp']))
	existing_tokens = db_cursor.fetchall()
	
	if len(existing_tokens) == 0:
		logger_api_token_mgmt.info(f'Adding token to cache for OID: {api_token_json["oid"]} | Session ID: {session}')
		
		db_cursor.execute("INSERT INTO authtokens(sessionid, oid, tid, exp, region, token) VALUES (?, ?, ?, ?, ?, ?)", (session, api_token_json['oid'], api_token_json['tid'], api_token_json['exp'], api_region, token))
		db_conn.commit()
	
	#Purge expired API tokens
	if (api_token_last_purge + config_api_token_purge_interval) <= int(time.time()):
		purge_expired_api_tokens()

def get_teams_user(user_mri, session_id, cip):
	api_base = 'https://teams.microsoft.com'
	api_urls = ['/api/mt/amer/beta/users/fetchShortProfile?isMailAddress=false&enableGuest=true&includeIBBarredUsers=true&skypeTeamsInfo=true', '/api/mt/amer/beta/users/fetchFederated']
	
	logger_get_teams_user.debug(f'Looking up Teams user: {user_mri} for Session ID: {session_id}')
	
	#Create thread-specific connection and cursor
	db_conn = sqlite3.connect(db_filepath)
	db_cursor = db_conn.cursor()
	
	db_cursor.execute("SELECT * FROM userlist WHERE mri = ?", (user_mri,))
	existing_user = db_cursor.fetchone()
	
	current_time = int(time.time())
	
	if existing_user is not None:
		if (existing_user[6] + config_user_lifetime) > current_time:
			logger_get_teams_user.debug(f'Found valid cache record for Teams user: {user_mri}')
			
			returned_user = [existing_user[1], existing_user[2], existing_user[3], existing_user[4], existing_user[5]]
			return [returned_user, '', '']
	
	#Grab an auth token to do a user lookup
	db_cursor.execute("SELECT * FROM authtokens WHERE sessionid = ? AND exp > ? ORDER BY exp DESC LIMIT 1", (session_id, current_time))
	token_item = db_cursor.fetchone()
	
	#TODO: Add error control for no token found
	
	token_item_tid = token_item[3]
	token_item_region = token_item[5]
	token = token_item[6]
	
	#Try internal user first, then try federated if not found
	for url in api_urls:
		new_url = api_base + url.replace('amer', token_item_region)
		req = urllib.request.Request(new_url)
		
		#req.data = urllib.parse.quote(json.dumps([user_mri]), encoding='utf-8')
		req.data = json.dumps([user_mri]).encode()
		
		req.add_header('Accept', 'application/json, text/plain, */*')
		req.add_header('Authorization', token)
		req.add_header('Content-Type', 'application/json;charset=UTF-8')
		
		#Add X-Forwarded-For if set in config
		if config_add_xff_header == True:
			req.add_header('X-Forwarded-For', cip)
		
		logger_get_teams_user.debug(f'Sending request to: "{new_url}" for user mri: "{user_mri}"')
		
		resp = urllib.request.urlopen(req)
		
		if resp.status == 200:
			body = resp.read()
			body_json = json.loads(body)
			
			#Ignore empty results
			if len(body_json['value']) > 0:
				if body_json['type'] == 'Microsoft.SkypeSpaces.MiddleTier.Models.IUserIdentity':
					returned_user = [body_json['value'][0]['mri'], body_json['value'][0]['email'], body_json['value'][0]['userPrincipalName'], token_item_tid, body_json['value'][0]['userType']]
					break
				elif body_json['type'] == 'Microsoft.SkypeSpaces.MiddleTier.Models.FederatedUser':
					returned_user = [body_json['value'][0]['mri'], body_json['value'][0]['email'], body_json['value'][0]['userPrincipalName'], body_json['value'][0]['tenantId'], body_json['value'][0]['type']]
					break
	
	if existing_user is not None:
		logger_get_teams_user.info(f'Updating cache record for user: {returned_user[0]} | {returned_user[1]}')
		
		query = "UPDATE"
		params = (returned_user[0], returned_user[1], returned_user[2], returned_user[3], returned_user[4], current_time, existing_user[0])
	else:
		logger_get_teams_user.info(f'Adding cache record for user mri: {returned_user[0]} | {returned_user[1]}')
		
		query = "INSERT"
		params = (returned_user[0], returned_user[1], returned_user[2], returned_user[3], returned_user[4], current_time)
	
	return [returned_user, query, params]

def get_conversation(host, url_path, token, cip, session_id):
	#Ignore participant mri prefixes (currently for bots)
	ignore_mri_prefixes = ['28']
	
	user_insert_query = "INSERT INTO userlist(mri, mail, upn, tid, type, savedtime) VALUES (?, ?, ?, ?, ?, ?)"
	user_update_query = "UPDATE userlist SET mri = ?, mail = ?, upn = ?, tid = ?, type = ?, savedtime = ? WHERE id = ?"
	
	conversation = TeamsConversation()
	
	current_time = int(time.time())
	
	token_json = get_json_from_auth_token(token)
	actor_oid = token_json['skypeid']
	tenant_id = token_json['tid']
	
	conv_base_types = [['SINGLE', '\/v\d\/users\/ME\/conversations\/(\d{1,2}:[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}_[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}@\S*\.(?:spaces|skype|v2))'], ['MULTI', '\/v\d\/users\/ME\/conversations\/(\d{1,2}:\S*@\S*\.(?:spaces|skype|v2))']]
	
	#Preset match not found
	conv_base_type = 'OTHER'
	id = ''
	
	for t in conv_base_types:
		match = re.search(t[1], url_path, re.IGNORECASE)
		
		if match != None:
			#Found match, set type and id
			conv_base_type = t[0]
			id = match.group(1)
			break
	
	is_federated = False
	
	db_cursor.execute("SELECT * FROM conversationmap WHERE conversationid = ?", (id,))
	existing_conversation = db_cursor.fetchone()
	
	if existing_conversation is not None:
		if (existing_conversation[4] + config_conversation_map_lifetime) > current_time:
			logger_get_conversation.debug(f'Found valid cache record for conversation id: {id}')
			
			with concurrent.futures.ThreadPoolExecutor(max_workers=config_max_userlookup_threads) as executor:
				futures = []
				user_update_values = []
				user_insert_values = []
				
				for teams_user in existing_conversation[2].split(','):
					futures.append(executor.submit(get_teams_user, teams_user, session_id, cip))
				
				for future in concurrent.futures.as_completed(futures):
					teams_user = future.result()[0]
					
					#Queue userlist SQL params returned from thread
					if future.result()[1] == 'INSERT':
						user_insert_values.append(future.result()[2])
					elif future.result()[1] == 'UPDATE':
						user_update_values.append(future.result()[2])
					
					if teams_user[0].endswith(actor_oid) == True:
						conversation.actor = teams_user[1].lower()
					else:
						conversation.participants.append(teams_user[1].lower())
					
					if teams_user[3] != tenant_id:
						is_federated = True
			
			#Execute userlist UPDATE SQL params returned from thread
			if len(user_update_values) > 0:
				db_cursor.executemany(user_update_query, user_update_values)
				db_conn.commit()
			
			#Execute userlist INSERT SQL params returned from thread
			if len(user_insert_values) > 0:
				db_cursor.executemany(user_insert_query, user_insert_values)
				db_conn.commit()
			
			conversation.type = existing_conversation[3]
			conversation.isfederated = is_federated
			
			return conversation
	
	#Existing valid conversation not found, continue with lookup
	
	if conv_base_type == 'SINGLE':
		req = urllib.request.Request('https://' + host + '/v1/threads/' + id + '/consumptionhorizons')
	elif conv_base_type == 'MULTI':
		req = urllib.request.Request('https://' + host + '/v1/threads/' + id + '/')
	else:
		#TODO: Add error throw here
		pass
	
	req.add_header('Accept', 'json')
	req.add_header('Authentication', token)
	
	#Add X-Forwarded-For if set in config
	if config_add_xff_header == True:
		req.add_header('X-Forwarded-For', cip)
	
	logger_get_conversation.debug(f'Sending conversation request to: {req.full_url}')
	
	resp = urllib.request.urlopen(req)
	
	body = resp.read()
	body_json = json.loads(body)
	
	participants = []
	conv_type = 'OTHER'
	
	if conv_base_type == 'SINGLE':
		conv_type = 'DIRECTCHAT'
		
		for m in body_json['consumptionhorizons']:
			participants.append(m['id'])
	elif conv_base_type == 'MULTI':
		if body_json['type'] == 'Thread':
			if body_json['properties']['threadType'] == 'chat':
				conv_type = 'GROUPCHAT'
			elif body_json['properties']['threadType'] == 'space':
				if 'spaceType' in body_json['properties']:
					if body_json['properties']['spaceType'] == 'standard':
						#General channel
						conv_type = 'TEAMCHATSTD'
				elif 'spaceTypes' in body_json['properties']:
					if 'parentSpaces' in body_json['properties']:
						conv_type = 'TEAMCHATPRIV'
			elif body_json['properties']['threadType'] == 'topic':
				#Non-general channel
				conv_type = 'TEAMCHATSTD'
				
				#Use core team orgid for member eumeration, swap ids in URL
				req.selector = req.selector.replace(id, body_json['properties']['spaceId'])
			elif body_json['properties']['threadType'] == 'meeting':
				conv_type = 'MEETINGCHAT'
			else:
				#other thread, throw error?
				pass
		else:
			#non-thead??? throw error
			pass
		
		req.selector = req.selector + "members?view=msnp24Equivalent&pageSize=100"
		
		done_reading = False
		
		#Pagination support
		while done_reading == False:
			logger_get_conversation.debug(f'Sending conversation member request to: {req.full_url}')
			
			resp = urllib.request.urlopen(req)
			body = resp.read()
			body_json = json.loads(body)
			
			for m in body_json['members']:
				#Exclude prefixes in ignore_mri_prefixes (currently for bots)
				if m['id'].split(':')[0] not in ignore_mri_prefixes:
					participants.append(m['id'])
			
			if 'nextLink' in body_json:
				req.full_url = body_json['nextLink']
			else:
				done_reading = True
	
	if existing_conversation is not None:
		logger_get_conversation.info(f'Updating cache record for conversation: {id} | {conv_type}')
		
		db_cursor.execute("UPDATE conversationmap SET conversationid = ?, participantmris = ?, conversationtype = ?, savedtime = ? WHERE id = ?", (id, ','.join(participants), conv_type, current_time, existing_conversation[0]))
	else:
		logger_get_conversation.info(f'Adding cache record for conversation: {id} | {conv_type}')
		
		db_cursor.execute("INSERT INTO conversationmap(conversationid, participantmris, conversationtype, savedtime) VALUES (?, ?, ?, ?)", (id, ','.join(participants), conv_type, current_time))
	
	db_conn.commit()
	
	with concurrent.futures.ThreadPoolExecutor(max_workers=config_max_userlookup_threads) as executor:
		futures = []
		user_update_values = []
		user_insert_values = []
		
		for teams_user in participants:
			futures.append(executor.submit(get_teams_user, teams_user, session_id, cip))
		
		for future in concurrent.futures.as_completed(futures):
			teams_user = future.result()[0]
			
			#Queue userlist SQL params returned from thread
			if future.result()[1] == 'INSERT':
				user_insert_values.append(future.result()[2])
			elif future.result()[1] == 'UPDATE':
				user_update_values.append(future.result()[2])
			
			if teams_user[0].endswith(actor_oid) == True:
				conversation.actor = teams_user[1].lower()
			else:
				conversation.participants.append(teams_user[1].lower())
			
			if teams_user[3] != tenant_id:
				is_federated = True
	
	#Execute userlist UPDATE SQL params returned from thread
	if len(user_update_values) > 0:
		db_cursor.executemany(user_update_query, user_update_values)
		db_conn.commit()
	
	#Execute userlist INSERT SQL params returned from thread
	if len(user_insert_values) > 0:
		db_cursor.executemany(user_insert_query, user_insert_values)
		db_conn.commit()
	
	conversation.type = conv_type
	conversation.isfederated = is_federated
	
	return conversation

class TeamsFirewall:
	def request(self, flow: mitmproxy.http.HTTPFlow):
		"""
			The full HTTP request has been read.
		"""
		
		host = flow.request.host.lower()
		path_decoded = urllib.parse.unquote(flow.request.path)
		
		client_ip = mitmproxy.utils.human.format_address(flow.client_conn.address).split(':')[0]
		
		#Add X-Forwarded-For header for all requests
		#https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-admin/user-id/enable-user-id.html#idea4ae539-91e4-4e58-9299-6d92dbf7e24a
		if config_add_xff_header == True:
			flow.request.headers['X-Forwarded-For'] = client_ip
		
		#Teams message (*.msg.teams.microsoft.com) requests
		if host.endswith('.msg.teams.microsoft.com'):
			#Only action authenticated requests
			if 'Authentication' in flow.request.headers:
				#Get event code
				event = get_teams_event_code(flow.request.method, path_decoded, str(flow.request.content))
				
				#Get tenant location
				skypetoken = flow.request.headers['Authentication']
				skypetoken_json = get_json_from_auth_token(skypetoken)
				
				if skypetoken_json['tid'] in config_tenant_ids:
					location = 'INTERNAL'
				else:
					location = 'EXTERNAL'
				
				#Get conversation object
				if event != 'OTHER':
					conversation = get_conversation(flow.request.host, path_decoded, skypetoken, client_ip, flow.request.headers['x-ms-session-id'])
					
					logger_core.debug(f'Conversation event. Event: {event} | Conversation type: {conversation.type} | Federated: {conversation.isfederated} | Actor: {conversation.actor} | Participant count: {len(conversation.participants)}')
				
				#Rule evalution execution
				if event != 'OTHER':
					for rule in config_rules:
						#EVENT and CONVERSATIONTYPE
						
						logger_core.debug(f'Starting rule evaluation for rule: {rule.name}')
						
						if (len(rule.event) == 0 or event in rule.event) and (len(rule.conversationtype) == 0 or conversation.type in rule.conversationtype):
							#LOCATION and FEDERATED (TODO: federated needs to support any if not filled)
							
							logger_rule_eval.debug(f'Event and type match')
							
							if (rule.location == None or rule.location == location) and (rule.isfederated is None or rule.isfederated == conversation.isfederated):
								#ACTORS and PARTICIPANTS (with wildcard support)
								
								logger_rule_eval.debug(f'Location and isfederated match')
								
								actor_match_found = False
								participant_match_found = False
								
								for actor in rule.actors:
									if '*' in actor:
										actor_regex = actor.replace('*', '\S+').replace('.', '\.')
										
										logger_rule_eval.debug(f'Comparing actor: {conversation.actor} to regex: {actor_regex}')
										
										if re.search(actor_regex, conversation.actor) is not None:
											logger_rule_eval.debug(f'Actor matches')
											
											actor_match_found = True
											break
									else:
										logger_rule_eval.debug(f'Comparing actor: {conversation.actor} to: {actor}')
										
										if actor == conversation.actor:
											logger_rule_eval.debug(f'Actor matches')
											
											actor_match_found = True
											break
								
								for participant in rule.participants:
									if '*' in participant:
										for cp in conversation.participants:
											participant_regex = participant.replace('*', '\S+').replace('.', '\.')
											
											logger_rule_eval.debug(f'Comparing participant: {cp} to regex: {participant_regex}')
											
											if re.search(participant_regex, cp) is not None:
												participant_match_found = True
												break
									else:
										logger_rule_eval.debug(f'Comparing participant: {cp} to: {conversation.participants}')
										
										if participant in conversation.participants:
											participant_match_found = True
											break
									
									#Break out of outer participant search if already broken out of regex search
									if participant_match_found == True:
										logger_rule_eval.debug(f'Participant matches')
										
										break
								
								if (len(rule.actors) == 0 or actor_match_found == True) and (len(rule.participants) == 0 or participant_match_found == True):
									logger_rule_eval.debug(f'Rule matches')
									
									for action in rule.actions:
										if action.action == 'BLOCK':
											logger_core.debug(f'Blocking conversation event')
											
											flow.response = mitmproxy.http.HTTPResponse.make(400, b'', {"Content-Type": "application/json"})
											#flow.kill()
										elif action.action == 'LOG':
											logger_core.debug(f'Logging conversation event')
											
											logger_core.info(f'{action.param1}')
										elif action.action == 'ADDHEADER':
											logger_core.debug(f'Adding header {action.param1}: {action.param2} to conversation event')
											
											flow.request.headers[action.param1] = action.param2
		
		#Intercept API calls for token caching
		elif host == ('teams.microsoft.com') and path_decoded.startswith('/api/mt'):
			if 'Authorization' in flow.request.headers and 'x-ms-session-id' in flow.request.headers:
				save_api_token(flow.request.headers['Authorization'], flow.request.headers['x-ms-session-id'], path_decoded)
		
		#All other requests
		else:
			pass

	def response(self, flow: mitmproxy.http.HTTPFlow):
		"""
			The full HTTP response has been read.
		"""

	def error(self, flow: mitmproxy.http.HTTPFlow):
		"""
			An HTTP error has occurred, e.g. invalid server responses, or
			interrupted connections. This is distinct from a valid server HTTP
			error response, which is simply a response with an HTTP error code.
		"""

#Load config file
try:
	script_dir = os.path.dirname(__file__)
	
	load_config()
	
	#Setup logger
	logger_core = logging.getLogger('TEAMSFIREWALL')
	logger_rule_eval = logging.getLogger('TEAMSFIREWALL.RULEEVAL')
	logger_api_token_mgmt = logging.getLogger('TEAMSFIREWALL.APITOKENMGMT')
	logger_get_teams_user = logging.getLogger('TEAMSFIREWALL.GETTEAMSUSER')
	logger_get_conversation = logging.getLogger('TEAMSFIREWALL.GETCONVERSATION')
	
	logger_core.setLevel(config_log_level_core)
	logger_rule_eval.setLevel(config_log_level_ruleeval)
	logger_api_token_mgmt.setLevel(config_log_level_apitokenmgmt)
	logger_get_teams_user.setLevel(config_log_level_getteamsuser)
	logger_get_conversation.setLevel(config_log_level_getconversation)
	
	#Needed to prevent flow to mitmproxy's logger object
	logger_core.propagate = False
	
	ch = logging.StreamHandler()
	#ch.setLevel(logging.DEBUG)
	
	fh = logging.handlers.RotatingFileHandler(script_dir + '\\teamsfirewall.log', mode='a', maxBytes=409600, backupCount=20)
	#fh.setLevel(logging.DEBUG)
	
	formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
	
	ch.setFormatter(formatter)
	fh.setFormatter(formatter)
	
	logger_core.handlers = [ch, fh]
	
	logger_core.info(f'Loaded {len(config_rules)} rule(s)')
	
	api_token_last_purge = 0
except:
	logger_core.error(f'Error loading config.')

db_filepath = script_dir + '\\teamsfirewall_cache.db'
db_conn = sqlite3.connect(db_filepath)
db_cursor = db_conn.cursor()

db_cursor.execute('''CREATE TABLE IF NOT EXISTS authtokens (id integer PRIMARY KEY, sessionid text NOT NULL, oid text NOT NULL, tid text NOT NULL, exp integer NOT NULL, region text NOT NULL, token text NOT NULL)''')
db_cursor.execute('''CREATE TABLE IF NOT EXISTS conversationmap (id integer PRIMARY KEY, conversationid text NOT NULL, participantmris text NOT NULL, conversationtype text NOT NULL, savedtime integer NOT NULL)''')
db_cursor.execute('''CREATE TABLE IF NOT EXISTS userlist (id integer PRIMARY KEY, mri text NOT NULL, mail text NOT NULL, upn text NOT NULL, tid text NOT NULL, type text NOT NULL, savedtime integer NOT NULL)''')
db_conn.commit()

logger_core.info(f'Configured cache db tables')

emptybody = "b''"

#Add firewall class
addons = [
	TeamsFirewall()
]
