package scanner

type RegisterRequest struct {
	WorkerId      string `json:"worker_id"`
	Address       string `json:"address"`
	MaxConcurrent int32  `json:"max_concurrent"`
}

type RegisterResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type GetTaskRequest struct {
	WorkerId string `json:"worker_id"`
}

type ScanTask struct {
	TaskId         string `json:"task_id"`
	IpStart        string `json:"ip_start"`
	IpEnd          string `json:"ip_end"`
	PortStart      int32  `json:"port_start"`
	PortEnd        int32  `json:"port_end"`
	TimeoutMs      int32  `json:"timeout_ms"`
	ScanMode       string `json:"scan_mode"`
	SourceIP       string `json:"source_ip"`
	EnableFragment bool   `json:"enable_fragment"`
	FragmentSize   int32  `json:"fragment_size"`
}

type GetTaskResponse struct {
	HasTask bool      `json:"has_task"`
	Task    *ScanTask `json:"task"`
	Message string    `json:"message"`
}

type PortResult struct {
	Ip        string `json:"ip"`
	Port      int32  `json:"port"`
	Open      bool   `json:"open"`
	LatencyMs int64  `json:"latency_ms"`
	Mode      string `json:"mode"`
}

type SubmitResultRequest struct {
	WorkerId  string        `json:"worker_id"`
	TaskId    string        `json:"task_id"`
	Results   []*PortResult `json:"results"`
	StartTime int64         `json:"start_time"`
	EndTime   int64         `json:"end_time"`
	Error     string        `json:"error"`
}

type SubmitResultResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type HeartbeatRequest struct {
	WorkerId    string   `json:"worker_id"`
	CurrentLoad int32    `json:"current_load"`
	Status      string   `json:"status"`
	ActiveTasks []string `json:"active_tasks"`
}

type HeartbeatResponse struct {
	Success           bool              `json:"success"`
	Message           string            `json:"message"`
	ServerTime        int64             `json:"server_time"`
	RevokedTasks      []string          `json:"revoked_tasks"`
	LeaseExtensions   map[string]int64  `json:"lease_extensions"`
}

type RenewLeaseRequest struct {
	WorkerId string   `json:"worker_id"`
	TaskIds  []string `json:"task_ids"`
}

type RenewLeaseResponse struct {
	Success      bool             `json:"success"`
	Message      string           `json:"message"`
	RevokedTasks []string         `json:"revoked_tasks"`
	LeaseExpiries map[string]int64 `json:"lease_expiries"`
}
