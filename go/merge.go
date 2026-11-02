package vpngate

import "sort"

func Merge(nodes []Node) []Node {
	type acc struct {
		node      Node
		hasPlugin bool
		hasCSV    bool
		fallback  string
	}
	merged := make(map[string]*acc, len(nodes))
	for _, raw := range nodes {
		if !validIPv4(raw.IP) {
			continue
		}
		a, ok := merged[raw.IP]
		if !ok {
			a = &acc{node: Node{
				IP:        raw.IP,
				SSLPorts:  []int{},
				FirstSeen: raw.FirstSeen,
				LastSeen:  raw.LastSeen,
			}}
			merged[raw.IP] = a
		}
		n := raw
		n.SSLPorts = normalizeSSLPorts(n.SSLPorts)
		if a.node.Country == "" {
			a.node.Country = n.Country
		}
		if a.node.FQDN == "" {
			a.node.FQDN = n.FQDN
		}
		if a.node.Hostname == "" {
			a.node.Hostname = n.Hostname
		}
		if n.L2TP {
			a.node.L2TP = true
		}
		if a.node.UDPPort == 0 && n.UDPPort != 0 {
			a.node.UDPPort = n.UDPPort
		}
		if n.Score > a.node.Score {
			a.node.Score = n.Score
		}
		if n.Sessions > a.node.Sessions {
			a.node.Sessions = n.Sessions
		}
		a.node.SSLPorts = append(a.node.SSLPorts, n.SSLPorts...)
		if n.FirstSeen < a.node.FirstSeen {
			a.node.FirstSeen = n.FirstSeen
		}
		if n.LastSeen > a.node.LastSeen {
			a.node.LastSeen = n.LastSeen
		}
		switch n.Source {
		case "plugin":
			a.hasPlugin = true
		case "csv":
			a.hasCSV = true
		case "both":
			a.hasPlugin = true
			a.hasCSV = true
		}
		if a.fallback == "" && n.Source != "" {
			a.fallback = n.Source
		}
	}

	out := make([]Node, 0, len(merged))
	for _, a := range merged {
		a.node.SSLPorts = normalizeSSLPorts(a.node.SSLPorts)
		switch {
		case a.hasPlugin && a.hasCSV:
			a.node.Source = "both"
		case a.hasPlugin:
			a.node.Source = "plugin"
		case a.hasCSV:
			a.node.Source = "csv"
		default:
			a.node.Source = a.fallback
		}
		out = append(out, a.node)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
