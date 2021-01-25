## TODO

### Near-term
 - Add logic to detect conversation join/leave events from conversations for faster updates
 - Add logic to harvest client-side user/conversation lookups (less on the fly lookups)
 - Enhance the "log" action with more robust functionality (ex. log to a database)
 - Improve error control

### Long-term
 - Add documentation/scripts around creating a TeamsFirewall service in Windows/Linux
 - Add external cache database functionality (ex. MS SQL, MySQL, etc.)
 - Secure API token storage
 - Test and add documentation around supporting mobile devices via Intune/per-app tunnels/Microsoft Tunnel
 - Look into using Docker containers and load balancer for increased per-server performance (external database would be a pre-requisite for this)
	 - Also look into other proxy platforms
