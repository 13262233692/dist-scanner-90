package worker

import (
	"fmt"
	"log"
	"net"
	"net/rpc"
	"sync"
	"time"

	pb "dist-scanner/proto"
	"dist-scanner/pkg/scanner"
)

type Worker struct {
	id            string
	address       string
	masterAddr    string
	maxConcurrent int
	client        *pb.ScannerClient
	conn          net.Conn
	config        scanner.ScanConfig
	currentLoad   int32
	status        string
	taskChan      chan *pb.ScanTask
	stopChan      chan struct{}
	wg            sync.WaitGroup
	activeTasks   map[string]bool
	activeTasksMu sync.Mutex
	revokedTasks  map[string]bool
	revokedMu     sync.Mutex
}

func NewWorker(id, address, masterAddr string, maxConcurrent int, timeout time.Duration, rateLimit int, scanMode, sourceIP string, enableFragment bool, fragmentSize int) *Worker {
	return &Worker{
		id:            id,
		address:       address,
		masterAddr:    masterAddr,
		maxConcurrent: maxConcurrent,
		config: scanner.ScanConfig{
			Timeout:        timeout,
			RateLimit:      rateLimit,
			Mode:           scanMode,
			SourceIP:       sourceIP,
			EnableFragment: enableFragment,
			FragmentSize:   fragmentSize,
		},
		taskChan:     make(chan *pb.ScanTask, maxConcurrent),
		stopChan:     make(chan struct{}),
		status:       "idle",
		activeTasks:  make(map[string]bool),
		revokedTasks: make(map[string]bool),
	}
}

func (w *Worker) Start() error {
	conn, err := net.DialTimeout("tcp", w.masterAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to master: %w", err)
	}
	w.conn = conn
	w.client = pb.NewScannerClient(rpc.NewClient(conn))

	if err := w.register(); err != nil {
		conn.Close()
		return err
	}

	go w.heartbeatLoop()
	go w.taskFetchLoop()
	go w.taskExecutionLoop()

	log.Printf("Worker %s started, connected to master %s", w.id, w.masterAddr)
	return nil
}

func (w *Worker) Stop() {
	close(w.stopChan)
	w.wg.Wait()
	if w.client != nil {
		w.client.Close()
	}
	log.Printf("Worker %s stopped", w.id)
}

func (w *Worker) register() error {
	resp, err := w.client.RegisterWorker(&pb.RegisterRequest{
		WorkerId:      w.id,
		Address:       w.address,
		MaxConcurrent: int32(w.maxConcurrent),
	})
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("registration rejected: %s", resp.Message)
	}
	log.Printf("Worker %s registered successfully", w.id)
	return nil
}

func (w *Worker) getActiveTaskIDs() []string {
	w.activeTasksMu.Lock()
	defer w.activeTasksMu.Unlock()

	ids := make([]string, 0, len(w.activeTasks))
	for id := range w.activeTasks {
		ids = append(ids, id)
	}
	return ids
}

func (w *Worker) isTaskRevoked(taskID string) bool {
	w.revokedMu.Lock()
	defer w.revokedMu.Unlock()
	return w.revokedTasks[taskID]
}

func (w *Worker) markTaskRevoked(taskID string) {
	w.revokedMu.Lock()
	w.revokedTasks[taskID] = true
	w.revokedMu.Unlock()
}

func (w *Worker) heartbeatLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopChan:
			return
		case <-ticker.C:
			activeTaskIDs := w.getActiveTaskIDs()

			resp, err := w.client.Heartbeat(&pb.HeartbeatRequest{
				WorkerId:    w.id,
				CurrentLoad: w.currentLoad,
				Status:      w.status,
				ActiveTasks: activeTaskIDs,
			})
			if err != nil {
				log.Printf("Heartbeat error: %v", err)
				continue
			}

			if len(resp.RevokedTasks) > 0 {
				for _, tid := range resp.RevokedTasks {
					log.Printf("Task %s revoked by master, will abort", tid)
					w.markTaskRevoked(tid)
				}
			}

			if len(resp.LeaseExtensions) > 0 {
				for tid := range resp.LeaseExtensions {
					w.activeTasksMu.Lock()
					if w.activeTasks[tid] {
						log.Printf("Lease extended for task %s", tid)
					}
					w.activeTasksMu.Unlock()
				}
			}
		}
	}
}

func (w *Worker) taskFetchLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopChan:
			return
		case <-ticker.C:
			if w.currentLoad >= int32(w.maxConcurrent) {
				continue
			}
			resp, err := w.client.GetTask(&pb.GetTaskRequest{
				WorkerId: w.id,
			})
			if err != nil {
				log.Printf("Get task error: %v", err)
				continue
			}
			if resp.HasTask && resp.Task != nil {
				log.Printf("Worker %s received task: %s (IP: %s-%s, Ports: %d-%d)",
					w.id, resp.Task.TaskId, resp.Task.IpStart, resp.Task.IpEnd,
					resp.Task.PortStart, resp.Task.PortEnd)
				select {
				case w.taskChan <- resp.Task:
					w.currentLoad++
				default:
					log.Printf("Task queue full, dropping task %s", resp.Task.TaskId)
				}
			}
		}
	}
}

func (w *Worker) taskExecutionLoop() {
	for {
		select {
		case <-w.stopChan:
			return
		case task := <-w.taskChan:
			w.wg.Add(1)
			go w.executeTask(task)
		}
	}
}

func (w *Worker) executeTask(task *pb.ScanTask) {
	defer w.wg.Done()
	defer func() { w.currentLoad-- }()

	w.activeTasksMu.Lock()
	w.activeTasks[task.TaskId] = true
	w.activeTasksMu.Unlock()

	defer func() {
		w.activeTasksMu.Lock()
		delete(w.activeTasks, task.TaskId)
		w.activeTasksMu.Unlock()
	}()

	if w.isTaskRevoked(task.TaskId) {
		log.Printf("Task %s was revoked before execution, skipping", task.TaskId)
		return
	}

	scanConfig := w.config
	if task.ScanMode != "" {
		scanConfig.Mode = task.ScanMode
	}
	if task.SourceIP != "" {
		scanConfig.SourceIP = task.SourceIP
	}
	if task.EnableFragment {
		scanConfig.EnableFragment = task.EnableFragment
	}
	if task.FragmentSize > 0 {
		scanConfig.FragmentSize = int(task.FragmentSize)
	}
	if task.TimeoutMs > 0 {
		scanConfig.Timeout = time.Duration(task.TimeoutMs) * time.Millisecond
	}

	taskScanner := scanner.NewSYNScannerWithConfig(scanConfig)

	w.status = "scanning"
	startTime := time.Now().UnixMilli()

	log.Printf("Starting task %s: scanning %s-%s, ports %d-%d, mode: %s",
		task.TaskId, task.IpStart, task.IpEnd, task.PortStart, task.PortEnd, scanConfig.Mode)

	scanResults, err := taskScanner.ScanRange(
		task.IpStart,
		task.IpEnd,
		int(task.PortStart),
		int(task.PortEnd),
		w.maxConcurrent,
	)

	if w.isTaskRevoked(task.TaskId) {
		log.Printf("Task %s was revoked during scan, discarding results", task.TaskId)
		w.status = "idle"
		return
	}

	endTime := time.Now().UnixMilli()
	w.status = "idle"

	var results []*pb.PortResult
	for _, r := range scanResults {
		results = append(results, &pb.PortResult{
			Ip:        r.IP,
			Port:      int32(r.Port),
			Open:      r.Open,
			LatencyMs: r.LatencyMs,
			Mode:      r.Mode,
		})
	}

	errorMsg := ""
	if err != nil {
		errorMsg = err.Error()
		log.Printf("Task %s error: %v", task.TaskId, err)
	}

	resp, err := w.client.SubmitResult(&pb.SubmitResultRequest{
		WorkerId:  w.id,
		TaskId:    task.TaskId,
		Results:   results,
		StartTime: startTime,
		EndTime:   endTime,
		Error:     errorMsg,
	})

	if err != nil {
		log.Printf("Failed to submit results for task %s: %v", task.TaskId, err)
	} else if resp != nil && !resp.Success {
		log.Printf("Master rejected results for task %s: %s", task.TaskId, resp.Message)
	} else {
		openCount := 0
		for _, r := range results {
			if r.Open {
				openCount++
			}
		}
		log.Printf("Task %s completed: %d open ports found, duration %dms, mode: %s",
			task.TaskId, openCount, endTime-startTime, scanConfig.Mode)
	}
}
