package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"dist-scanner/internal/common"
	"dist-scanner/internal/master"
	pb "dist-scanner/proto"
)

func main() {
	var (
		addr       = flag.String("addr", ":50051", "master listen address")
		ipRange    = flag.String("ip", "", "IP range (e.g., 192.168.1.1-192.168.1.100 or 192.168.1.0/24)")
		portRange  = flag.String("ports", "1-1000", "port range (e.g., 1-1000 or 80,443,8080)")
		timeout    = flag.Int("timeout", 500, "scan timeout in milliseconds")
		ipsPerTask = flag.Int("ips-per-task", 10, "number of IPs per task")
		wait       = flag.Bool("wait", true, "wait for scan completion")
		waitTimeout = flag.Int("wait-timeout", 3600, "wait timeout in seconds")
		workers    = flag.Bool("workers", false, "list connected workers")
		results    = flag.Bool("results", false, "show scan results")
		status     = flag.Bool("status", false, "show scan status")
		scanMode   = flag.String("scan-mode", "auto", "scan mode: auto, tcp-connect, syn, syn-fragment")
		sourceIP   = flag.String("source-ip", "", "custom source IP (requires root privileges)")
		fragment   = flag.Bool("fragment", false, "enable IP fragmentation for SYN scans")
		fragSize   = flag.Int("frag-size", 8, "fragment size in bytes")
	)

	flag.Parse()

	m := master.NewMaster(*addr)
	if err := m.Start(); err != nil {
		log.Fatalf("Failed to start master: %v", err)
	}
	defer m.Stop()

	if *workers {
		showWorkers(m)
		return
	}

	if *status {
		showStatus(m)
		return
	}

	if *results {
		showResults(m)
		return
	}

	if *ipRange == "" {
		fmt.Println("Error: -ip is required to start a scan")
		flag.Usage()
		os.Exit(1)
	}

	ipStart, ipEnd, err := common.ParseIPRange(*ipRange)
	if err != nil {
		log.Fatalf("Invalid IP range: %v", err)
	}

	portStart, portEnd, err := common.ParsePortRange(*portRange)
	if err != nil {
		log.Fatalf("Invalid port range: %v", err)
	}

	err = m.AddScanJob(ipStart, ipEnd, portStart, portEnd, *timeout, *ipsPerTask, *scanMode, *sourceIP, *fragment, *fragSize)
	if err != nil {
		log.Fatalf("Failed to add scan job: %v", err)
	}

	fmt.Printf("Scan job submitted:\n")
	fmt.Printf("  IP range:    %s - %s\n", ipStart, ipEnd)
	fmt.Printf("  Port range:  %d - %d\n", portStart, portEnd)
	fmt.Printf("  Timeout:     %dms\n", *timeout)
	fmt.Printf("  IPs/task:    %d\n", *ipsPerTask)
	fmt.Printf("  Scan mode:   %s\n", *scanMode)
	if *sourceIP != "" {
		fmt.Printf("  Source IP:   %s\n", *sourceIP)
	}
	if *fragment {
		fmt.Printf("  Fragment:    enabled (size: %d bytes)\n", *fragSize)
	}

	if *wait {
		fmt.Println("\nWaiting for workers to connect and complete scan...")
		fmt.Println("Press Ctrl+C to stop waiting (results will be preserved)")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				showStatus(m)
			}
		}()

		select {
		case <-sigChan:
			fmt.Println("\nInterrupted, showing current results...")
		case done := <-waitForScan(m, time.Duration(*waitTimeout)*time.Second):
			if done {
				fmt.Println("\nScan completed!")
			} else {
				fmt.Println("\nWait timeout reached")
			}
		}

		showResults(m)
	}
}

func waitForScan(m *master.Master, timeout time.Duration) <-chan bool {
	ch := make(chan bool, 1)
	go func() {
		ch <- m.WaitForCompletion(timeout)
	}()
	return ch
}

func showWorkers(m *master.Master) {
	workers := m.GetWorkers()
	if len(workers) == 0 {
		fmt.Println("No workers connected")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "WORKER ID\tADDRESS\tMAX CONCURRENT\tCURRENT LOAD\tSTATUS\tLAST HEARTBEAT")
	for _, worker := range workers {
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n",
			worker.ID,
			worker.Address,
			worker.MaxConcurrent,
			worker.CurrentLoad,
			worker.Status,
			worker.LastHeartbeat.Format("15:04:05"),
		)
	}
	w.Flush()
}

func showStatus(m *master.Master) {
	total, completed := m.GetProgress()
	workers := m.GetWorkers()

	fmt.Printf("\n=== Scan Status ===\n")
	fmt.Printf("Total tasks:     %d\n", total)
	fmt.Printf("Completed:       %d\n", completed)
	if total > 0 {
		fmt.Printf("Progress:        %.1f%%\n", float64(completed)/float64(total)*100)
	}
	fmt.Printf("Active workers:  %d\n", len(workers))
	for _, w := range workers {
		fmt.Printf("  - %s: %s (load: %d/%d)\n", w.ID, w.Status, w.CurrentLoad, w.MaxConcurrent)
	}
}

func showResults(m *master.Master) {
	results := m.GetResults()
	if len(results) == 0 {
		fmt.Println("No open ports found")
		return
	}

	fmt.Printf("\n=== Scan Results: %d open ports found ===\n", len(results))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tLATENCY(ms)\tMODE")
	for _, r := range results {
		if r.Open {
			fmt.Fprintf(w, "%s\t%d\t%d\t%s\n", r.Ip, r.Port, r.LatencyMs, r.Mode)
		}
	}
	w.Flush()

	saveResultsToFile(results, "scan_results.txt")
}

func saveResultsToFile(results []*pb.PortResult, filename string) {
	f, err := os.Create(filename)
	if err != nil {
		log.Printf("Warning: failed to save results to file: %v", err)
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "Distributed Port Scanner Results\n")
	fmt.Fprintf(f, "Generated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(f, "Total open ports: %d\n\n", len(results))
	fmt.Fprintf(f, "IP\tPORT\tLATENCY(ms)\tMODE\n")
	for _, r := range results {
		if r.Open {
			fmt.Fprintf(f, "%s\t%d\t%d\t%s\n", r.Ip, r.Port, r.LatencyMs, r.Mode)
		}
	}
	fmt.Printf("\nResults saved to %s\n", filename)
}
