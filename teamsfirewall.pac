function FindProxyForURL(url, host)
{
	/* Normalize the URL for pattern matching */
	url = url.toLowerCase();
	host = host.toLowerCase();
	
	teamsfirewall = "PROXY teamsfirewall.domain.com:8080";
	
	/* Send message traffic via TeamsFirewall */
	if (shExpMatch(host, "*.msg.teams.microsoft.com"))
		return teamsfirewall;
	
	/* Send API traffic via TeamsFirewall */
	if (shExpMatch(host, "teams.microsoft.com"))
		return teamsfirewall;
	
	/* All other traffic DIRECT */
	return "DIRECT";
}
