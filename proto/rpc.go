package scanner

import (
	"net/rpc"
)

const (
	ServiceName        = "ScannerService"
	MethodRegister     = ServiceName + ".RegisterWorker"
	MethodGetTask      = ServiceName + ".GetTask"
	MethodSubmitResult = ServiceName + ".SubmitResult"
	MethodHeartbeat    = ServiceName + ".Heartbeat"
	MethodRenewLease   = ServiceName + ".RenewLease"
)

type ScannerService interface {
	RegisterWorker(args *RegisterRequest, reply *RegisterResponse) error
	GetTask(args *GetTaskRequest, reply *GetTaskResponse) error
	SubmitResult(args *SubmitResultRequest, reply *SubmitResultResponse) error
	Heartbeat(args *HeartbeatRequest, reply *HeartbeatResponse) error
	RenewLease(args *RenewLeaseRequest, reply *RenewLeaseResponse) error
}

func RegisterScannerService(server *rpc.Server, srv ScannerService) error {
	return server.RegisterName(ServiceName, srv)
}

type ScannerClient struct {
	client *rpc.Client
}

func NewScannerClient(client *rpc.Client) *ScannerClient {
	return &ScannerClient{client: client}
}

func (c *ScannerClient) RegisterWorker(args *RegisterRequest) (*RegisterResponse, error) {
	reply := &RegisterResponse{}
	err := c.client.Call(MethodRegister, args, reply)
	return reply, err
}

func (c *ScannerClient) GetTask(args *GetTaskRequest) (*GetTaskResponse, error) {
	reply := &GetTaskResponse{}
	err := c.client.Call(MethodGetTask, args, reply)
	return reply, err
}

func (c *ScannerClient) SubmitResult(args *SubmitResultRequest) (*SubmitResultResponse, error) {
	reply := &SubmitResultResponse{}
	err := c.client.Call(MethodSubmitResult, args, reply)
	return reply, err
}

func (c *ScannerClient) Heartbeat(args *HeartbeatRequest) (*HeartbeatResponse, error) {
	reply := &HeartbeatResponse{}
	err := c.client.Call(MethodHeartbeat, args, reply)
	return reply, err
}

func (c *ScannerClient) RenewLease(args *RenewLeaseRequest) (*RenewLeaseResponse, error) {
	reply := &RenewLeaseResponse{}
	err := c.client.Call(MethodRenewLease, args, reply)
	return reply, err
}

func (c *ScannerClient) Close() error {
	return c.client.Close()
}
