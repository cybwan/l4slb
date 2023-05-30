package server

import (
	"context"
	"fmt"
	"github.com/cybwan/l4slb/pkg/helpers"
	"net"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cybwan/l4slb/pkg/bpf/progs/root"
	"github.com/cybwan/l4slb/pkg/pb"
	"github.com/cybwan/l4slb/pkg/slb"
)

const (
	// ServerType is the type identifier for the L4Slb Control server
	ServerType = "L4Slb Control Service"
)

// Server implements L4Slb Control Services
type Server struct {
	pb.UnimplementedSlbServiceServer

	lb *slb.FlomeshLb
}

// NewL4SlbControlServer creates a new L4Slb Control Service server
func NewL4SlbControlServer() *Server {
	server := Server{}
	server.lb = slb.NewFlomeshLb(slb.NewFlomeshLbConfig())
	return &server
}

// Start starts the L4Slb Control server
func (s *Server) Start(ctx context.Context, cancel context.CancelFunc, dev string, port int) (func(), error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal().Err(err)
	}

	if err := root.Load(); err != nil {
		log.Fatal().Err(err)
	}

	release := root.Attach(dev)

	grpcServer, lis, err := NewGrpc(ServerType, port)
	if err != nil {
		return release, fmt.Errorf("error starting L4Slb Control Server: %w", err)
	}

	pb.RegisterSlbServiceServer(grpcServer.GetServer(), s)

	err = grpcServer.GrpcServe(ctx, cancel, lis, nil)
	if err != nil {
		return release, fmt.Errorf("error starting L4Slb Control Server: %w", err)
	}

	return release, nil
}

func (s *Server) ChangeMac(ctx context.Context, mac *pb.Mac) (*pb.Bool, error) {
	response := new(pb.Bool)
	macBytes, err := helpers.ConvertMacToUint(mac.Mac)
	if err != nil {
		log.Error().Err(err)
		response.Success = false
		return response, nil
	}
	success := s.lb.ChangeMac(macBytes)
	response.Success = success
	return response, nil
}

func (s *Server) GetMac(ctx context.Context, empty *pb.Empty) (*pb.Mac, error) {
	macBytes := s.lb.GetMac()
	mac := net.HardwareAddr(macBytes)
	response := new(pb.Mac)
	response.Mac = mac.String()
	return response, nil
}

func (s *Server) AddVip(ctx context.Context, meta *pb.VipMeta) (*pb.Bool, error) {
	vk := translateVipObject(meta.GetVip())
	success := s.lb.AddVip(vk, uint32(meta.Flags))
	response := new(pb.Bool)
	response.Success = success
	return response, nil
}

func (s *Server) DelVip(ctx context.Context, vip *pb.Vip) (*pb.Bool, error) {
	vk := translateVipObject(vip)
	success := s.lb.DelVip(vk)
	response := new(pb.Bool)
	response.Success = success
	return response, nil
}

func (s *Server) GetAllVips(ctx context.Context, empty *pb.Empty) (*pb.Vips, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) ModifyVip(ctx context.Context, meta *pb.VipMeta) (*pb.Bool, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) ModifyReal(ctx context.Context, meta *pb.RealMeta) (*pb.Bool, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) GetVipFlags(ctx context.Context, vip *pb.Vip) (*pb.Flags, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) GetRealFlags(ctx context.Context, r *pb.Real) (*pb.Flags, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) AddRealForVip(ctx context.Context, vip *pb.RealForVip) (*pb.Bool, error) {
	vk := translateVipObject(vip.GetVip())
	nr := translateRealObject(vip.GetReal())
	success := s.lb.AddRealForVip(nr, vk)
	response := new(pb.Bool)
	response.Success = success
	return response, nil
}

func (s *Server) DelRealForVip(ctx context.Context, vip *pb.RealForVip) (*pb.Bool, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) ModifyRealsForVip(ctx context.Context, vip *pb.ModifiedRealsForVip) (*pb.Bool, error) {
	var action slb.ModifyAction
	nreals := make([]slb.NewReal, 0)

	switch vip.Action {
	case pb.Action_ADD:
		action = slb.ADD
	case pb.Action_DEL:
		action = slb.DEL
	default:
		break
	}
	vk := translateVipObject(vip.GetVip())
	for _, r := range vip.GetReal().GetReals() {
		nr := translateRealObject(r)
		nreals = append(nreals, *nr)
	}
	success := s.lb.ModifyRealsForVip(action, nreals, vk)
	response := new(pb.Bool)
	response.Success = success
	return response, nil
}

func (s *Server) GetRealsForVip(ctx context.Context, vip *pb.Vip) (*pb.Reals, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) ModifyQuicRealsMapping(ctx context.Context, reals *pb.ModifiedQuicReals) (*pb.Bool, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) GetQuicRealsMapping(ctx context.Context, empty *pb.Empty) (*pb.QuicReals, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) GetStatsForVip(ctx context.Context, vip *pb.Vip) (*pb.Stats, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) GetLruStats(ctx context.Context, empty *pb.Empty) (*pb.Stats, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) GetLruMissStats(ctx context.Context, empty *pb.Empty) (*pb.Stats, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) GetLruFallbackStats(ctx context.Context, empty *pb.Empty) (*pb.Stats, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) GetIcmpTooBigStats(ctx context.Context, empty *pb.Empty) (*pb.Stats, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) AddHealthcheckerDst(ctx context.Context, healthcheck *pb.Healthcheck) (*pb.Bool, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) DelHealthcheckerDst(ctx context.Context, somark *pb.Somark) (*pb.Bool, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) GetHealthcheckersDst(ctx context.Context, empty *pb.Empty) (*pb.HcMap, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) mustEmbedUnimplementedSlbServiceServer() {
	//TODO implement me
	panic("implement me")
}

func translateVipObject(vip *pb.Vip) *slb.VipKey {
	vk := new(slb.VipKey)
	vk.Address = vip.GetAddress()
	vk.Port = uint16(vip.GetPort())
	vk.Proto = uint8(vip.GetProtocol())
	return vk
}

func translateRealObject(real *pb.Real) *slb.NewReal {
	nr := new(slb.NewReal)
	nr.Address = real.GetAddress()
	nr.Weight = uint32(real.GetWeight())
	nr.Flags = uint8(real.GetFlags())
	return nr
}

func translateQuicRealObject(real *pb.QuicReal) *slb.QuicReal {
	qr := new(slb.QuicReal)
	qr.Address = real.GetAddress()
	qr.Id = uint32(real.GetId())
	return qr
}
