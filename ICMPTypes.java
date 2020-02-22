public enum ICMPTypes{
	// Longest is 41 CHARS
	// 1 - ETHERNET
	//   11 - ARP
	//   12 - IP
	//     121 - TCP
	//     122 - UDP
	//     123 - ICMP_TYPE_CODE
	ICMP12300("Echo Reply"),
	ICMP12330("Destination Network Unreachable"),
	ICMP12331("Destination Host Unreachable"),
	ICMP12332("Destination Protocol Unreachable"),
	ICMP12333("Destination Port Unreachable"),
	ICMP12334("Fragmentation Required and DF Flag Set"),
	ICMP12335("Source Route Failed"),
	ICMP12336("Destination Network Unknown"),
	ICMP12337("Destination Host Unknown"),
	ICMP12338("Source Host Isolated"),
	ICMP12339("Network Administratively Prohibited"),
	ICMP123310("Host Administratively Prohibited"),
	ICMP123311("Network Unreachable for ToS"),
	ICMP123312("Host Unreachable for ToS"),
	ICMP123313("Communication Administratively Prohibited"),
	ICMP123314("Host Precedence Violation"),
	ICMP123315("Precedence Cutoff in Effect"),
	ICMP12350("Redirect Datagram for the Network"),
	ICMP12351("Redirect Datagram for the Host"),
	ICMP12352("Redirect Datagram for the ToS & Network"),
	ICMP12353("Redirect Datagram for the ToS & Host"),
	ICMP12380("Echo Request (Ping)"),
	ICMP12390("Router Advertisement"),
	ICMP123100("Router Discovery/Selection/Solicitation"),
	ICMP123110("TTL Expired in Transit "),
	ICMP123111("Fragment Reassembly Time Exceeded"),
	ICMP123120("Pointer Indicates the Error"),
	ICMP123121("Missing a Required Option "),
	ICMP123122("Bad Length"),
	ICMP123130("Timestamp"),
	ICMP123140("Timestamp Reply");

	private final String message;

	ICMPTypes(String message){
		this.message = message;
	}

	public String getMessage() { return message; }

}