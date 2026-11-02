package vpngate

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
)

type ResultExporter interface {
	ExportResults(w io.Writer, results []Result) error
}

type JSONExporter struct{}

func (JSONExporter) Format() string { return "json" }

func (JSONExporter) Export(w io.Writer, nodes []Node) error {
	return WriteNodesJSON(w, nodes)
}

type CSVExporter struct{}

func (CSVExporter) Format() string { return "csv" }

var csvHeader = []string{"ip", "port", "country", "egress", "elapsed_ms", "ok"}

func (CSVExporter) Export(w io.Writer, nodes []Node) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, n := range nodes {
		port := 0
		ports := normalizeSSLPorts(n.SSLPorts)
		if len(ports) > 0 {
			port = ports[0]
		}
		row := []string{n.IP, strconv.Itoa(port), n.Country, "", "0", "false"}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func (CSVExporter) ExportResults(w io.Writer, results []Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, r := range results {
		row := []string{
			r.IP,
			strconv.Itoa(r.Port),
			r.Country,
			r.Egress,
			strconv.FormatInt(r.ElapsedMS, 10),
			strconv.FormatBool(r.OK),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

type PlainExporter struct{}

func (PlainExporter) Format() string { return "plain" }

func (PlainExporter) Export(w io.Writer, nodes []Node) error {
	for _, n := range nodes {
		ports := normalizeSSLPorts(n.SSLPorts)
		if len(ports) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s:%d\n", n.IP, ports[0]); err != nil {
			return err
		}
	}
	return nil
}

func (PlainExporter) ExportResults(w io.Writer, results []Result) error {
	for _, r := range results {
		if r.Port <= 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s:%d\n", r.IP, r.Port); err != nil {
			return err
		}
	}
	return nil
}

type SingBoxExporter struct {
	Certificates CertBundle
	BasePort     int
}

func (SingBoxExporter) Format() string { return "singbox" }

func (e SingBoxExporter) Export(w io.Writer, nodes []Node) error {
	best := -1
	for i, n := range nodes {
		if len(normalizeSSLPorts(n.SSLPorts)) == 0 {
			continue
		}
		if best < 0 || n.Score > nodes[best].Score {
			best = i
		}
	}
	if best < 0 {
		return fmt.Errorf("singbox: no node with ssl_ports")
	}
	return e.write(w, nodes[best])
}

func (e SingBoxExporter) ExportResults(w io.Writer, results []Result) error {
	best := -1
	for i, r := range results {
		if !r.OK {
			continue
		}
		if best < 0 || r.ElapsedMS < results[best].ElapsedMS {
			best = i
		}
	}
	if best < 0 {
		return fmt.Errorf("singbox: no successful result")
	}
	r := results[best]
	return e.write(w, Node{
		IP:       r.IP,
		Country:  r.Country,
		SSLPorts: []int{r.Port},
		Source:   "plugin",
	})
}

func (e SingBoxExporter) write(w io.Writer, node Node) error {
	basePort := e.BasePort
	if basePort <= 0 {
		basePort = 20000
	}
	data, err := GenerateBatchConfig([]Node{node}, e.Certificates, basePort)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func ResultsToNodes(results []Result) []Node {
	nodes := make([]Node, 0, len(results))
	for _, r := range results {
		if !r.OK {
			continue
		}
		nodes = append(nodes, Node{
			IP:       r.IP,
			Country:  r.Country,
			SSLPorts: []int{r.Port},
			Source:   "plugin",
		})
	}
	return nodes
}
