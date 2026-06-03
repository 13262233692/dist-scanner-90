package master

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"sort"
	"sync"
	"time"

	pb "dist-scanner/proto"
)

const (
	TaskStatusPending    = "pending"
	TaskStatusAssigned   = "assigned"
	TaskStatusSuspect    = "suspect"
	TaskStatusCompleted  = "completed"

	WorkerStatusActive   = "active"
	WorkerStatusSuspect  = "suspect"

	DefaultLeaseDuration     = 120 * time.Second
	SuspectTimeout           = 30 * time.Second
	DeadTimeout              = 90 * time.Second
	MonitorInterval          = 10 * time.Second
)

type WorkerInfo struct {
	ID            string
	Address       string
	MaxConcurrent int32
	CurrentLoad   int32
	Status        string
	LastHeartbeat time.Time
	ActiveTasks   map[string]bool
}

type TaskInfo struct {
	Task         *pb.ScanTask
	AssignedTo   string
	Status       string
	StartTime    int64
	EndTime      int64
	Results      []*pb.PortResult
	Error        string
	LeaseExpiry  time.Time
	SuspectSince time.Time
}

type ipRangeKey struct {
	IpStart   string
	IpEnd     string
	PortStart int32
	PortEnd   int32
}

type Master struct {
	address        string
	server         *rpc.Server
	listener       net.Listener
	workers        map[string]*WorkerInfo
	workersMu      sync.RWMutex
	taskQueue      []*pb.ScanTask
	assigned       map[string]*TaskInfo
	completed      map[string]*TaskInfo
	tasksMu        sync.Mutex
	ipRangeOwned   map[ipRangeKey]string
	results        map[string]*pb.PortResult
	resultsMu      sync.Mutex
	totalTasks     uint64
	completedTasks uint64
	stopChan       chan struct{}
}

func NewMaster(address string) *Master {
	return &Master{
		address:      address,
		server:       rpc.NewServer(),
		workers:      make(map[string]*WorkerInfo),
		taskQueue:    make([]*pb.ScanTask, 0),
		assigned:     make(map[string]*TaskInfo),
		completed:    make(map[string]*TaskInfo),
		ipRangeOwned: make(map[ipRangeKey]string),
		results:      make(map[string]*pb.PortResult),
		stopChan:     make(chan struct{}),
	}
}

func (m *Master) Start() error {
	lis, err := net.Listen("tcp", m.address)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	m.listener = lis

	if err := pb.RegisterScannerService(m.server, m); err != nil {
		return fmt.Errorf("failed to register service: %w", err)
	}

	go m.acceptConnections()
	go m.workerMonitor()

	log.Printf("Master started on %s", m.address)
	return nil
}

func (m *Master) acceptConnections() {
	for {
		select {
		case <-m.stopChan:
			return
		default:
			conn, err := m.listener.Accept()
			if err != nil {
				select {
				case <-m.stopChan:
					return
				default:
					log.Printf("Accept error: %v", err)
					continue
				}
			}
			go m.server.ServeConn(conn)
		}
	}
}

func (m *Master) Stop() {
	close(m.stopChan)
	if m.listener != nil {
		m.listener.Close()
	}
	log.Printf("Master stopped")
}

func (m *Master) RegisterWorker(args *pb.RegisterRequest, reply *pb.RegisterResponse) error {
	m.workersMu.Lock()
	defer m.workersMu.Unlock()

	m.workers[args.WorkerId] = &WorkerInfo{
		ID:            args.WorkerId,
		Address:       args.Address,
		MaxConcurrent: args.MaxConcurrent,
		CurrentLoad:   0,
		Status:        WorkerStatusActive,
		LastHeartbeat: time.Now(),
		ActiveTasks:   make(map[string]bool),
	}

	log.Printf("Worker registered: %s (max concurrent: %d)", args.WorkerId, args.MaxConcurrent)
	reply.Success = true
	reply.Message = "registered"
	return nil
}

func (m *Master) GetTask(args *pb.GetTaskRequest, reply *pb.GetTaskResponse) error {
	m.workersMu.RLock()
	worker, exists := m.workers[args.WorkerId]
	m.workersMu.RUnlock()

	if !exists {
		reply.HasTask = false
		reply.Message = "worker not registered"
		return nil
	}

	if worker.Status == WorkerStatusSuspect {
		reply.HasTask = false
		reply.Message = "worker in suspect state, no new tasks"
		return nil
	}

	m.tasksMu.Lock()
	defer m.tasksMu.Unlock()

	if len(m.taskQueue) == 0 {
		reply.HasTask = false
		reply.Message = "no tasks available"
		return nil
	}

	var task *pb.ScanTask
	for i, t := range m.taskQueue {
		key := ipRangeKey{IpStart: t.IpStart, IpEnd: t.IpEnd, PortStart: t.PortStart, PortEnd: t.PortEnd}
		if _, owned := m.ipRangeOwned[key]; !owned {
			task = t
			m.taskQueue = append(m.taskQueue[:i], m.taskQueue[i+1:]...)
			break
		}
	}

	if task == nil {
		reply.HasTask = false
		reply.Message = "no non-overlapping tasks available"
		return nil
	}

	key := ipRangeKey{IpStart: task.IpStart, IpEnd: task.IpEnd, PortStart: task.PortStart, PortEnd: task.PortEnd}
	m.ipRangeOwned[key] = args.WorkerId

	leaseExpiry := time.Now().Add(DefaultLeaseDuration)
	m.assigned[task.TaskId] = &TaskInfo{
		Task:        task,
		AssignedTo:  args.WorkerId,
		Status:      TaskStatusAssigned,
		StartTime:   time.Now().UnixMilli(),
		LeaseExpiry: leaseExpiry,
	}

	m.workersMu.Lock()
	worker.ActiveTasks[task.TaskId] = true
	worker.CurrentLoad++
	worker.Status = WorkerStatusActive
	m.workersMu.Unlock()

	log.Printf("Task %s assigned to worker %s (lease expires: %s)", task.TaskId, args.WorkerId, leaseExpiry.Format("15:04:05"))
	reply.HasTask = true
	reply.Task = task
	reply.Message = "task assigned"
	return nil
}

func (m *Master) SubmitResult(args *pb.SubmitResultRequest, reply *pb.SubmitResultResponse) error {
	m.tasksMu.Lock()

	if _, alreadyDone := m.completed[args.TaskId]; alreadyDone {
		m.tasksMu.Unlock()
		reply.Success = true
		reply.Message = "already completed (duplicate ignored)"
		log.Printf("Duplicate result for task %s from %s ignored", args.TaskId, args.WorkerId)
		return nil
	}

	taskInfo, exists := m.assigned[args.TaskId]
	if !exists {
		m.tasksMu.Unlock()
		reply.Success = false
		reply.Message = "task not found or lease expired"
		return nil
	}

	if taskInfo.AssignedTo != args.WorkerId {
		m.tasksMu.Unlock()
		reply.Success = false
		reply.Message = "task not assigned to this worker"
		log.Printf("Worker %s submitted result for task %s assigned to %s (rejected)",
			args.WorkerId, args.TaskId, taskInfo.AssignedTo)
		return nil
	}

	taskInfo.Status = TaskStatusCompleted
	taskInfo.EndTime = args.EndTime
	taskInfo.Results = args.Results
	taskInfo.Error = args.Error
	m.completed[args.TaskId] = taskInfo
	delete(m.assigned, args.TaskId)
	m.completedTasks++

	key := ipRangeKey{
		IpStart:   taskInfo.Task.IpStart,
		IpEnd:     taskInfo.Task.IpEnd,
		PortStart: taskInfo.Task.PortStart,
		PortEnd:   taskInfo.Task.PortEnd,
	}
	delete(m.ipRangeOwned, key)
	m.tasksMu.Unlock()

	m.resultsMu.Lock()
	for _, r := range args.Results {
		if r.Open {
			dedupKey := fmt.Sprintf("%s:%d", r.Ip, r.Port)
			if _, dup := m.results[dedupKey]; !dup {
				m.results[dedupKey] = r
			}
		}
	}
	m.resultsMu.Unlock()

	m.workersMu.Lock()
	if worker, exists := m.workers[args.WorkerId]; exists {
		delete(worker.ActiveTasks, args.TaskId)
		worker.CurrentLoad--
		if worker.CurrentLoad <= 0 {
			worker.CurrentLoad = 0
		}
	}
	m.workersMu.Unlock()

	openCount := 0
	for _, r := range args.Results {
		if r.Open {
			openCount++
		}
	}
	duration := args.EndTime - args.StartTime
	log.Printf("Task %s completed by %s: %d open ports, duration %dms",
		args.TaskId, args.WorkerId, openCount, duration)

	reply.Success = true
	reply.Message = "result received"
	return nil
}

func (m *Master) Heartbeat(args *pb.HeartbeatRequest, reply *pb.HeartbeatResponse) error {
	m.workersMu.Lock()

	worker, exists := m.workers[args.WorkerId]
	if !exists {
		m.workersMu.Unlock()
		reply.Success = false
		reply.Message = "worker not registered"
		return nil
	}

	worker.LastHeartbeat = time.Now()
	worker.CurrentLoad = args.CurrentLoad
	worker.Status = WorkerStatusActive

	activeSet := make(map[string]bool, len(args.ActiveTasks))
	for _, tid := range args.ActiveTasks {
		activeSet[tid] = true
	}

	for tid := range worker.ActiveTasks {
		if !activeSet[tid] {
			delete(worker.ActiveTasks, tid)
		}
	}
	for _, tid := range args.ActiveTasks {
		worker.ActiveTasks[tid] = true
	}

	m.tasksMu.Lock()
	var revokedTasks []string
	leaseExtensions := make(map[string]int64)
	for _, tid := range args.ActiveTasks {
		if taskInfo, ok := m.assigned[tid]; ok && taskInfo.AssignedTo == args.WorkerId {
			if taskInfo.Status == TaskStatusSuspect {
				revokedTasks = append(revokedTasks, tid)
			} else {
				newExpiry := time.Now().Add(DefaultLeaseDuration)
				taskInfo.LeaseExpiry = newExpiry
				taskInfo.SuspectSince = time.Time{}
				leaseExtensions[tid] = newExpiry.UnixMilli()
			}
		}
	}
	m.tasksMu.Unlock()

	m.workersMu.Unlock()

	reply.Success = true
	reply.Message = "heartbeat received"
	reply.ServerTime = time.Now().UnixMilli()
	reply.RevokedTasks = revokedTasks
	reply.LeaseExtensions = leaseExtensions
	return nil
}

func (m *Master) RenewLease(args *pb.RenewLeaseRequest, reply *pb.RenewLeaseResponse) error {
	m.workersMu.RLock()
	_, exists := m.workers[args.WorkerId]
	m.workersMu.RUnlock()

	if !exists {
		reply.Success = false
		reply.Message = "worker not registered"
		return nil
	}

	m.tasksMu.Lock()
	defer m.tasksMu.Unlock()

	var revokedTasks []string
	leaseExpiries := make(map[string]int64)

	for _, tid := range args.TaskIds {
		taskInfo, ok := m.assigned[tid]
		if !ok {
			revokedTasks = append(revokedTasks, tid)
			continue
		}

		if taskInfo.AssignedTo != args.WorkerId {
			revokedTasks = append(revokedTasks, tid)
			continue
		}

		if taskInfo.Status == TaskStatusSuspect {
			revokedTasks = append(revokedTasks, tid)
			continue
		}

		newExpiry := time.Now().Add(DefaultLeaseDuration)
		taskInfo.LeaseExpiry = newExpiry
		taskInfo.SuspectSince = time.Time{}
		leaseExpiries[tid] = newExpiry.UnixMilli()
	}

	reply.Success = true
	reply.Message = "lease renewed"
	reply.RevokedTasks = revokedTasks
	reply.LeaseExpiries = leaseExpiries
	return nil
}

func (m *Master) AddScanJob(ipStart, ipEnd string, portStart, portEnd int, timeoutMs int, ipsPerTask int, scanMode, sourceIP string, enableFragment bool, fragmentSize int) error {
	startUint, err := ipToUint32(ipStart)
	if err != nil {
		return err
	}
	endUint, err := ipToUint32(ipEnd)
	if err != nil {
		return err
	}

	m.tasksMu.Lock()
	defer m.tasksMu.Unlock()

	taskID := 0
	for ipStart := startUint; ipStart <= endUint; {
		ipEnd := ipStart + uint32(ipsPerTask) - 1
		if ipEnd > endUint {
			ipEnd = endUint
		}

		taskID++
		task := &pb.ScanTask{
			TaskId:         fmt.Sprintf("scan-%d-%d", time.Now().UnixNano(), taskID),
			IpStart:        uint32ToIP(ipStart),
			IpEnd:          uint32ToIP(ipEnd),
			PortStart:      int32(portStart),
			PortEnd:        int32(portEnd),
			TimeoutMs:      int32(timeoutMs),
			ScanMode:       scanMode,
			SourceIP:       sourceIP,
			EnableFragment: enableFragment,
			FragmentSize:   int32(fragmentSize),
		}
		m.taskQueue = append(m.taskQueue, task)
		m.totalTasks++

		ipStart = ipEnd + 1
	}

	log.Printf("Added %d scan tasks for IP range %s-%s, ports %d-%d, mode: %s",
		taskID, ipStart, ipEnd, portStart, portEnd, scanMode)
	return nil
}

func (m *Master) workerMonitor() {
	ticker := time.NewTicker(MonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.checkWorkerHealth()
			m.checkLeaseExpirations()
		}
	}
}

func (m *Master) checkWorkerHealth() {
	m.workersMu.Lock()
	defer m.workersMu.Unlock()

	now := time.Now()

	for id, worker := range m.workers {
		heartbeatAge := now.Sub(worker.LastHeartbeat)

		switch worker.Status {
		case WorkerStatusActive:
			if heartbeatAge > SuspectTimeout {
				worker.Status = WorkerStatusSuspect
				log.Printf("Worker %s suspect (no heartbeat for %v)", id, heartbeatAge.Round(time.Second))
			}

		case WorkerStatusSuspect:
			if heartbeatAge > DeadTimeout {
				log.Printf("Worker %s dead (no heartbeat for %v), requeuing tasks", id, heartbeatAge.Round(time.Second))

				m.tasksMu.Lock()
				for taskID, taskInfo := range m.assigned {
					if taskInfo.AssignedTo == id {
						m.requeueTask(taskID, taskInfo)
					}
				}
				m.tasksMu.Unlock()

				delete(m.workers, id)
			}
		}
	}
}

func (m *Master) checkLeaseExpirations() {
	m.tasksMu.Lock()
	defer m.tasksMu.Unlock()

	now := time.Now()

	for taskID, taskInfo := range m.assigned {
		if taskInfo.Status == TaskStatusSuspect {
			continue
		}

		if now.After(taskInfo.LeaseExpiry) {
			m.workersMu.RLock()
			worker, workerExists := m.workers[taskInfo.AssignedTo]
			m.workersMu.RUnlock()

			if !workerExists {
				log.Printf("Task %s lease expired, worker %s gone, requeuing", taskID, taskInfo.AssignedTo)
				m.requeueTask(taskID, taskInfo)
				continue
			}

			taskInfo.Status = TaskStatusSuspect
			taskInfo.SuspectSince = now

			m.workersMu.Lock()
			worker.Status = WorkerStatusSuspect
			m.workersMu.Unlock()

			log.Printf("Task %s lease expired on worker %s (marked suspect, not requeued yet)",
				taskID, taskInfo.AssignedTo)
		}
	}

	for taskID, taskInfo := range m.assigned {
		if taskInfo.Status != TaskStatusSuspect {
			continue
		}

		m.workersMu.RLock()
		worker, workerExists := m.workers[taskInfo.AssignedTo]
		m.workersMu.RUnlock()

		stillSuspect := !workerExists || worker.Status == WorkerStatusSuspect
		if stillSuspect && !taskInfo.SuspectSince.IsZero() && now.Sub(taskInfo.SuspectSince) > SuspectTimeout {
			log.Printf("Task %s suspect timeout (worker %s unresponsive for %v), requeuing",
				taskID, taskInfo.AssignedTo, now.Sub(taskInfo.SuspectSince).Round(time.Second))
			m.requeueTask(taskID, taskInfo)
		}
	}
}

func (m *Master) requeueTask(taskID string, taskInfo *TaskInfo) {
	key := ipRangeKey{
		IpStart:   taskInfo.Task.IpStart,
		IpEnd:     taskInfo.Task.IpEnd,
		PortStart: taskInfo.Task.PortStart,
		PortEnd:   taskInfo.Task.PortEnd,
	}
	delete(m.ipRangeOwned, key)

	delete(m.assigned, taskID)

	m.taskQueue = append(m.taskQueue, taskInfo.Task)
	log.Printf("Task %s requeued (IP: %s-%s, Ports: %d-%d)",
		taskID, taskInfo.Task.IpStart, taskInfo.Task.IpEnd,
		taskInfo.Task.PortStart, taskInfo.Task.PortEnd)
}

func (m *Master) GetWorkers() []*WorkerInfo {
	m.workersMu.RLock()
	defer m.workersMu.RUnlock()

	workers := make([]*WorkerInfo, 0, len(m.workers))
	for _, w := range m.workers {
		workers = append(workers, w)
	}
	return workers
}

func (m *Master) GetResults() []*pb.PortResult {
	m.resultsMu.Lock()
	defer m.resultsMu.Unlock()

	results := make([]*pb.PortResult, 0, len(m.results))
	for _, r := range m.results {
		results = append(results, r)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Ip != results[j].Ip {
			return results[i].Ip < results[j].Ip
		}
		return results[i].Port < results[j].Port
	})

	return results
}

func (m *Master) GetProgress() (total, completed uint64) {
	m.tasksMu.Lock()
	defer m.tasksMu.Unlock()
	return m.totalTasks, m.completedTasks
}

func (m *Master) WaitForCompletion(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return false
		case <-ticker.C:
			total, completed := m.GetProgress()
			if total > 0 && completed >= total {
				return true
			}
			if time.Now().After(deadline) {
				return false
			}
		}
	}
}

func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}
	return binary.BigEndian.Uint32(ip), nil
}

func uint32ToIP(ipUint uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipUint)
	return ip.String()
}
