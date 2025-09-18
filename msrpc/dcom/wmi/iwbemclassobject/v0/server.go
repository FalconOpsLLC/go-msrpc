package iwbemclassobject

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf16"

	dcerpc "github.com/FalconOpsLLC/go-msrpc/dcerpc"
	errors "github.com/FalconOpsLLC/go-msrpc/dcerpc/errors"
	uuid "github.com/FalconOpsLLC/go-msrpc/midl/uuid"
	iunknown "github.com/FalconOpsLLC/go-msrpc/msrpc/dcom/iunknown/v0"
	ndr "github.com/FalconOpsLLC/go-msrpc/ndr"
)

var (
	_ = context.Background
	_ = fmt.Errorf
	_ = utf16.Encode
	_ = strings.TrimPrefix
	_ = ndr.ZeroString
	_ = (*uuid.UUID)(nil)
	_ = (*dcerpc.SyntaxID)(nil)
	_ = (*errors.Error)(nil)
	_ = iunknown.GoPackage
)

// IWbemClassObject server interface.
type ClassObjectServer interface {

	// IUnknown base class.
	iunknown.UnknownServer

	// SpawnDerivedClass operation.
	SpawnDerivedClass(context.Context, *SpawnDerivedClassRequest) (*SpawnDerivedClassResponse, error)

	// Put operation.
	Put(context.Context, *PutRequest) (*PutResponse, error)
}

func RegisterClassObjectServer(conn dcerpc.Conn, o ClassObjectServer, opts ...dcerpc.Option) {
	conn.RegisterServer(NewClassObjectServerHandle(o), append(opts, dcerpc.WithAbstractSyntax(ClassObjectSyntaxV0_0))...)
}

func NewClassObjectServerHandle(o ClassObjectServer) dcerpc.ServerHandle {
	return func(ctx context.Context, opNum int, r ndr.Reader) (dcerpc.Operation, error) {
		return ClassObjectServerHandle(ctx, o, opNum, r)
	}
}

func ClassObjectServerHandle(ctx context.Context, o ClassObjectServer, opNum int, r ndr.Reader) (dcerpc.Operation, error) {
	if opNum < 3 {
		// IUnknown base method.
		return iunknown.UnknownServerHandle(ctx, o, opNum, r)
	}
	switch opNum {
	case 3: // SpawnDerivedClass
		op := &xxx_SpawnDerivedClassOperation{}
		if err := op.UnmarshalNDRRequest(ctx, r); err != nil {
			return nil, err
		}
		req := &SpawnDerivedClassRequest{}
		req.xxx_FromOp(ctx, op)
		resp, err := o.SpawnDerivedClass(ctx, req)
		return resp.xxx_ToOp(ctx, op), err
	case 4: // Put
		op := &xxx_PutOperation{}
		if err := op.UnmarshalNDRRequest(ctx, r); err != nil {
			return nil, err
		}
		req := &PutRequest{}
		req.xxx_FromOp(ctx, op)
		resp, err := o.Put(ctx, req)
		return resp.xxx_ToOp(ctx, op), err
	}
	return nil, nil
}

// Unimplemented IWbemClassObject
type UnimplementedClassObjectServer struct {
	iunknown.UnimplementedUnknownServer
}

func (UnimplementedClassObjectServer) SpawnDerivedClass(context.Context, *SpawnDerivedClassRequest) (*SpawnDerivedClassResponse, error) {
	return nil, dcerpc.ErrNotImplemented
}
func (UnimplementedClassObjectServer) Put(context.Context, *PutRequest) (*PutResponse, error) {
	return nil, dcerpc.ErrNotImplemented
}

var _ ClassObjectServer = (*UnimplementedClassObjectServer)(nil)
