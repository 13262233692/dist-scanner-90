package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dist-scanner/internal/common"
	"dist-scanner/internal/worker"
)

func main() {
	var (
		masterAddr  = flag.String("master", "localhost:50051", "master server address")
		workerAddr  = flag.String("addr", ":0", "worker listen address")
		workerID    = flag.String("id", "", "worker ID (auto-generated if not set)")
		concurrency = flag.Int("concurrency", 100, "max concurrent scans")
		timeout     = flag.Int("timeout", 500, "scan timeout in milliseconds")
		rateLimit   = flag.Int("rate-limit", 1000, "max packets per second")
		scanMode    = flag.String("scan-mode", "auto", "scan mode: auto, tcp-connect, syn, syn-fragment")
		sourceIP    = flag.String("source-ip", "", "custom source IP (requires root privileges)")
		fragment    = flag.Bool("fragment", false, "enable IP fragmentation for SYN scans")
		fragSize    = flag.Int("frag-size", 8, "fragment size in bytes")
	)

	flag.Parse()

	id := *workerID
	if id == "" {
		id = common.GenerateWorkerID()
	}

	w := worker.NewWorker(
		id,
		*workerAddr,
		*masterAddr,
		*concurrency,
		time.Duration(*timeout)*time.Millisecond,
		*rateLimit,
		*scanMode,
		*sourceIP,
		*fragment,
		*fragSize,
	)

	if err := w.Start(); err != nil {
		log.Fatalf("Failed to start worker: %v", err)
	}
	defer w.Stop()

	fmt.Printf("Worker started:\n")
	fmt.Printf("  ID:            %s\n", id)
	fmt.Printf("  Master:        %s\n", *masterAddr)
	fmt.Printf("  Concurrency:   %d\n", *concurrency)
	fmt.Printf("  Timeout:       %dms\n", *timeout)
	fmt.Printf("  Rate limit:    %d pps\n", *rateLimit)
	fmt.Printf("  Scan mode:     %s\n", *scanMode)
	if *sourceIP != "" {
		fmt.Printf("  Source IP:     %s\n", *sourceIP)
	}
	if *fragment {
		fmt.Printf("  Fragment:      enabled (size: %d bytes)\n", *fragSize)
	}
	fmt.Println("\nPress Ctrl+C to stop")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nStopping worker...")
}
