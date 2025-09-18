package iwbemclassobject

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf16"

	dcerpc "github.com/FalconOpsLLC/go-msrpc/dcerpc"
	errors "github.com/FalconOpsLLC/go-msrpc/dcerpc/errors"
	uuid "github.com/FalconOpsLLC/go-msrpc/midl/uuid"
	dcom "github.com/FalconOpsLLC/go-msrpc/msrpc/dcom"
	iunknown "github.com/FalconOpsLLC/go-msrpc/msrpc/dcom/iunknown/v0"
	oaut "github.com/FalconOpsLLC/go-msrpc/msrpc/dcom/oaut"
	wmi "github.com/FalconOpsLLC/go-msrpc/msrpc/dcom/wmi"
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
	_ = dcom.GoPackage
	_ = iunknown.GoPackage
	_ = wmi.GoPackage
	_ = oaut.GoPackage
)

var (
	// import guard
	GoPackage = "dcom/wmi"
)

var (
	// IWbemClassObject interface identifier dc12a681-737f-11cf-884d-00aa004b2e24
	ClassObjectIID = &dcom.IID{Data1: 0xdc12a681, Data2: 0x737f, Data3: 0x11cf, Data4: []byte{0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}}
	// Syntax UUID
	ClassObjectSyntaxUUID = &uuid.UUID{TimeLow: 0xdc12a681, TimeMid: 0x737f, TimeHiAndVersion: 0x11cf, ClockSeqHiAndReserved: 0x88, ClockSeqLow: 0x4d, Node: [6]uint8{0x0, 0xaa, 0x0, 0x4b, 0x2e, 0x24}}
	// Syntax ID
	ClassObjectSyntaxV0_0 = &dcerpc.SyntaxID{IfUUID: ClassObjectSyntaxUUID, IfVersionMajor: 0, IfVersionMinor: 0}
)

// IWbemClassObject interface.
type ClassObjectClient interface {

	// IUnknown retrieval method.
	Unknown() iunknown.UnknownClient

	// SpawnDerivedClass operation.
	SpawnDerivedClass(context.Context, *SpawnDerivedClassRequest, ...dcerpc.CallOption) (*SpawnDerivedClassResponse, error)

	// Put operation.
	Put(context.Context, *PutRequest, ...dcerpc.CallOption) (*PutResponse, error)

	// AlterContext alters the client context.
	AlterContext(context.Context, ...dcerpc.Option) error

	// Conn returns the client connection (unsafe)
	Conn() dcerpc.Conn

	// IPID sets the object interface identifier.
	IPID(context.Context, *dcom.IPID) ClassObjectClient
}

type xxx_DefaultClassObjectClient struct {
	iunknown.UnknownClient
	cc   dcerpc.Conn
	ipid *dcom.IPID
}

func (o *xxx_DefaultClassObjectClient) Unknown() iunknown.UnknownClient {
	return o.UnknownClient
}

func (o *xxx_DefaultClassObjectClient) SpawnDerivedClass(ctx context.Context, in *SpawnDerivedClassRequest, opts ...dcerpc.CallOption) (*SpawnDerivedClassResponse, error) {
	op := in.xxx_ToOp(ctx, nil)
	if _, ok := dcom.HasIPID(opts); !ok {
		if o.ipid != nil {
			opts = append(opts, dcom.WithIPID(o.ipid))
		} else {
			return nil, fmt.Errorf("%s: ipid is missing", op.OpName())
		}
	}
	if err := o.cc.Invoke(ctx, op, opts...); err != nil {
		return nil, err
	}
	out := &SpawnDerivedClassResponse{}
	out.xxx_FromOp(ctx, op)
	if op.Return != int32(0) {
		return out, fmt.Errorf("%s: %w", op.OpName(), errors.New(ctx, op.Return))
	}
	return out, nil
}

func (o *xxx_DefaultClassObjectClient) Put(ctx context.Context, in *PutRequest, opts ...dcerpc.CallOption) (*PutResponse, error) {
	op := in.xxx_ToOp(ctx, nil)
	if _, ok := dcom.HasIPID(opts); !ok {
		if o.ipid != nil {
			opts = append(opts, dcom.WithIPID(o.ipid))
		} else {
			return nil, fmt.Errorf("%s: ipid is missing", op.OpName())
		}
	}
	if err := o.cc.Invoke(ctx, op, opts...); err != nil {
		return nil, err
	}
	out := &PutResponse{}
	out.xxx_FromOp(ctx, op)
	if op.Return != int32(0) {
		return out, fmt.Errorf("%s: %w", op.OpName(), errors.New(ctx, op.Return))
	}
	return out, nil
}

func (o *xxx_DefaultClassObjectClient) AlterContext(ctx context.Context, opts ...dcerpc.Option) error {
	return o.cc.AlterContext(ctx, opts...)
}

func (o *xxx_DefaultClassObjectClient) Conn() dcerpc.Conn {
	return o.cc
}

func (o *xxx_DefaultClassObjectClient) IPID(ctx context.Context, ipid *dcom.IPID) ClassObjectClient {
	if ipid == nil {
		ipid = &dcom.IPID{}
	}
	return &xxx_DefaultClassObjectClient{
		UnknownClient: o.UnknownClient.IPID(ctx, ipid),
		cc:            o.cc,
		ipid:          ipid,
	}
}

func NewClassObjectClient(ctx context.Context, cc dcerpc.Conn, opts ...dcerpc.Option) (ClassObjectClient, error) {
	var err error
	if !dcom.IsSuperclass(opts) {
		cc, err = cc.Bind(ctx, append(opts, dcerpc.WithAbstractSyntax(ClassObjectSyntaxV0_0))...)
		if err != nil {
			return nil, err
		}
	}
	base, err := iunknown.NewUnknownClient(ctx, cc, append(opts, dcom.Superclass(cc))...)
	if err != nil {
		return nil, err
	}
	ipid, ok := dcom.HasIPID(opts)
	if ok {
		base = base.IPID(ctx, ipid)
	}
	return &xxx_DefaultClassObjectClient{
		UnknownClient: base,
		cc:            cc,
		ipid:          ipid,
	}, nil
}

// xxx_SpawnDerivedClassOperation structure represents the SpawnDerivedClass operation
type xxx_SpawnDerivedClassOperation struct {
	This     *dcom.ORPCThis   `idl:"name:This" json:"this"`
	That     *dcom.ORPCThat   `idl:"name:That" json:"that"`
	Flags    int32            `idl:"name:lFlags" json:"flags"`
	NewClass *wmi.ClassObject `idl:"name:ppNewClass" json:"new_class"`
	Return   int32            `idl:"name:Return" json:"return"`
}

func (o *xxx_SpawnDerivedClassOperation) OpNum() int { return 3 }

func (o *xxx_SpawnDerivedClassOperation) OpName() string {
	return "/IWbemClassObject/v0/SpawnDerivedClass"
}

func (o *xxx_SpawnDerivedClassOperation) xxx_PrepareRequestPayload(ctx context.Context) error {
	if hook, ok := (interface{})(o).(interface{ AfterPrepareRequestPayload(context.Context) error }); ok {
		if err := hook.AfterPrepareRequestPayload(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (o *xxx_SpawnDerivedClassOperation) MarshalNDRRequest(ctx context.Context, w ndr.Writer) error {
	if err := o.xxx_PrepareRequestPayload(ctx); err != nil {
		return err
	}
	// This {in} (1:{alias=ORPCTHIS}(struct))
	{
		if o.This != nil {
			if err := o.This.MarshalNDR(ctx, w); err != nil {
				return err
			}
		} else {
			if err := (&dcom.ORPCThis{}).MarshalNDR(ctx, w); err != nil {
				return err
			}
		}
		if err := w.WriteDeferred(); err != nil {
			return err
		}
	}
	// lFlags {in} (1:(int32))
	{
		if err := w.WriteData(o.Flags); err != nil {
			return err
		}
	}
	return nil
}

func (o *xxx_SpawnDerivedClassOperation) UnmarshalNDRRequest(ctx context.Context, w ndr.Reader) error {
	// This {in} (1:{alias=ORPCTHIS}(struct))
	{
		if o.This == nil {
			o.This = &dcom.ORPCThis{}
		}
		if err := o.This.UnmarshalNDR(ctx, w); err != nil {
			return err
		}
		if err := w.ReadDeferred(); err != nil {
			return err
		}
	}
	// lFlags {in} (1:(int32))
	{
		if err := w.ReadData(&o.Flags); err != nil {
			return err
		}
	}
	return nil
}

func (o *xxx_SpawnDerivedClassOperation) xxx_PrepareResponsePayload(ctx context.Context) error {
	if hook, ok := (interface{})(o).(interface{ AfterPrepareResponsePayload(context.Context) error }); ok {
		if err := hook.AfterPrepareResponsePayload(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (o *xxx_SpawnDerivedClassOperation) MarshalNDRResponse(ctx context.Context, w ndr.Writer) error {
	if err := o.xxx_PrepareResponsePayload(ctx); err != nil {
		return err
	}
	// That {out} (1:{alias=ORPCTHAT}(struct))
	{
		if o.That != nil {
			if err := o.That.MarshalNDR(ctx, w); err != nil {
				return err
			}
		} else {
			if err := (&dcom.ORPCThat{}).MarshalNDR(ctx, w); err != nil {
				return err
			}
		}
		if err := w.WriteDeferred(); err != nil {
			return err
		}
	}
	// ppNewClass {out} (1:{pointer=ref}*(2)*(1))(2:{alias=IWbemClassObject}(interface))
	{
		if o.NewClass != nil {
			_ptr_ppNewClass := ndr.MarshalNDRFunc(func(ctx context.Context, w ndr.Writer) error {
				if o.NewClass != nil {
					if err := o.NewClass.MarshalNDR(ctx, w); err != nil {
						return err
					}
				} else {
					if err := (&wmi.ClassObject{}).MarshalNDR(ctx, w); err != nil {
						return err
					}
				}
				return nil
			})
			if err := w.WritePointer(&o.NewClass, _ptr_ppNewClass); err != nil {
				return err
			}
		} else {
			if err := w.WritePointer(nil); err != nil {
				return err
			}
		}
		if err := w.WriteDeferred(); err != nil {
			return err
		}
	}
	// Return {out} (1:{alias=HRESULT}(int32))
	{
		if err := w.WriteData(o.Return); err != nil {
			return err
		}
	}
	return nil
}

func (o *xxx_SpawnDerivedClassOperation) UnmarshalNDRResponse(ctx context.Context, w ndr.Reader) error {
	// That {out} (1:{alias=ORPCTHAT}(struct))
	{
		if o.That == nil {
			o.That = &dcom.ORPCThat{}
		}
		if err := o.That.UnmarshalNDR(ctx, w); err != nil {
			return err
		}
		if err := w.ReadDeferred(); err != nil {
			return err
		}
	}
	// ppNewClass {out} (1:{pointer=ref}*(2)*(1))(2:{alias=IWbemClassObject}(interface))
	{
		_ptr_ppNewClass := ndr.UnmarshalNDRFunc(func(ctx context.Context, w ndr.Reader) error {
			if o.NewClass == nil {
				o.NewClass = &wmi.ClassObject{}
			}
			if err := o.NewClass.UnmarshalNDR(ctx, w); err != nil {
				return err
			}
			return nil
		})
		_s_ppNewClass := func(ptr interface{}) { o.NewClass = *ptr.(**wmi.ClassObject) }
		if err := w.ReadPointer(&o.NewClass, _s_ppNewClass, _ptr_ppNewClass); err != nil {
			return err
		}
		if err := w.ReadDeferred(); err != nil {
			return err
		}
	}
	// Return {out} (1:{alias=HRESULT}(int32))
	{
		if err := w.ReadData(&o.Return); err != nil {
			return err
		}
	}
	return nil
}

// SpawnDerivedClassRequest structure represents the SpawnDerivedClass operation request
type SpawnDerivedClassRequest struct {
	// This: ORPCTHIS structure that is used to send ORPC extension data to the server.
	This  *dcom.ORPCThis `idl:"name:This" json:"this"`
	Flags int32          `idl:"name:lFlags" json:"flags"`
}

func (o *SpawnDerivedClassRequest) xxx_ToOp(ctx context.Context, op *xxx_SpawnDerivedClassOperation) *xxx_SpawnDerivedClassOperation {
	if op == nil {
		op = &xxx_SpawnDerivedClassOperation{}
	}
	if o == nil {
		return op
	}
	op.This = o.This
	op.Flags = o.Flags
	return op
}

func (o *SpawnDerivedClassRequest) xxx_FromOp(ctx context.Context, op *xxx_SpawnDerivedClassOperation) {
	if o == nil {
		return
	}
	o.This = op.This
	o.Flags = op.Flags
}
func (o *SpawnDerivedClassRequest) MarshalNDR(ctx context.Context, w ndr.Writer) error {
	return o.xxx_ToOp(ctx, nil).MarshalNDRRequest(ctx, w)
}
func (o *SpawnDerivedClassRequest) UnmarshalNDR(ctx context.Context, r ndr.Reader) error {
	_o := &xxx_SpawnDerivedClassOperation{}
	if err := _o.UnmarshalNDRRequest(ctx, r); err != nil {
		return err
	}
	o.xxx_FromOp(ctx, _o)
	return nil
}

// SpawnDerivedClassResponse structure represents the SpawnDerivedClass operation response
type SpawnDerivedClassResponse struct {
	// That: ORPCTHAT structure that is used to return ORPC extension data to the client.
	That     *dcom.ORPCThat   `idl:"name:That" json:"that"`
	NewClass *wmi.ClassObject `idl:"name:ppNewClass" json:"new_class"`
	// Return: The SpawnDerivedClass return value.
	Return int32 `idl:"name:Return" json:"return"`
}

func (o *SpawnDerivedClassResponse) xxx_ToOp(ctx context.Context, op *xxx_SpawnDerivedClassOperation) *xxx_SpawnDerivedClassOperation {
	if op == nil {
		op = &xxx_SpawnDerivedClassOperation{}
	}
	if o == nil {
		return op
	}
	op.That = o.That
	op.NewClass = o.NewClass
	op.Return = o.Return
	return op
}

func (o *SpawnDerivedClassResponse) xxx_FromOp(ctx context.Context, op *xxx_SpawnDerivedClassOperation) {
	if o == nil {
		return
	}
	o.That = op.That
	o.NewClass = op.NewClass
	o.Return = op.Return
}
func (o *SpawnDerivedClassResponse) MarshalNDR(ctx context.Context, w ndr.Writer) error {
	return o.xxx_ToOp(ctx, nil).MarshalNDRResponse(ctx, w)
}
func (o *SpawnDerivedClassResponse) UnmarshalNDR(ctx context.Context, r ndr.Reader) error {
	_o := &xxx_SpawnDerivedClassOperation{}
	if err := _o.UnmarshalNDRResponse(ctx, r); err != nil {
		return err
	}
	o.xxx_FromOp(ctx, _o)
	return nil
}

// xxx_PutOperation structure represents the Put operation
type xxx_PutOperation struct {
	This   *dcom.ORPCThis `idl:"name:This" json:"this"`
	That   *dcom.ORPCThat `idl:"name:That" json:"that"`
	Name   string         `idl:"name:wszName" json:"name"`
	Flags  int32          `idl:"name:lFlags" json:"flags"`
	Value  *oaut.Variant  `idl:"name:pVal" json:"value"`
	Type   wmi.Cimtype    `idl:"name:Type" json:"type"`
	Return int32          `idl:"name:Return" json:"return"`
}

func (o *xxx_PutOperation) OpNum() int { return 4 }

func (o *xxx_PutOperation) OpName() string { return "/IWbemClassObject/v0/Put" }

func (o *xxx_PutOperation) xxx_PrepareRequestPayload(ctx context.Context) error {
	if hook, ok := (interface{})(o).(interface{ AfterPrepareRequestPayload(context.Context) error }); ok {
		if err := hook.AfterPrepareRequestPayload(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (o *xxx_PutOperation) MarshalNDRRequest(ctx context.Context, w ndr.Writer) error {
	if err := o.xxx_PrepareRequestPayload(ctx); err != nil {
		return err
	}
	// This {in} (1:{alias=ORPCTHIS}(struct))
	{
		if o.This != nil {
			if err := o.This.MarshalNDR(ctx, w); err != nil {
				return err
			}
		} else {
			if err := (&dcom.ORPCThis{}).MarshalNDR(ctx, w); err != nil {
				return err
			}
		}
		if err := w.WriteDeferred(); err != nil {
			return err
		}
	}
	// wszName {in} (1:{alias=LPCWSTR}*(1)[dim:0,string](wchar))
	{
		if err := ndr.WriteUTF16String(ctx, w, o.Name); err != nil {
			return err
		}
	}
	// lFlags {in} (1:(int32))
	{
		if err := w.WriteData(o.Flags); err != nil {
			return err
		}
	}
	// pVal {in} (1:{pointer=ref}*(2))(2:{alias=VARIANT}*(1))(3:{alias=_VARIANT}(struct))
	{
		if o.Value != nil {
			_ptr_pVal := ndr.MarshalNDRFunc(func(ctx context.Context, w ndr.Writer) error {
				if o.Value != nil {
					if err := o.Value.MarshalNDR(ctx, w); err != nil {
						return err
					}
				} else {
					if err := (&oaut.Variant{}).MarshalNDR(ctx, w); err != nil {
						return err
					}
				}
				return nil
			})
			if err := w.WritePointer(&o.Value, _ptr_pVal); err != nil {
				return err
			}
		} else {
			if err := w.WritePointer(nil); err != nil {
				return err
			}
		}
		if err := w.WriteDeferred(); err != nil {
			return err
		}
	}
	// Type {in} (1:{alias=CIMTYPE}(enum))
	{
		if err := w.WriteEnum(uint16(o.Type)); err != nil {
			return err
		}
	}
	return nil
}

func (o *xxx_PutOperation) UnmarshalNDRRequest(ctx context.Context, w ndr.Reader) error {
	// This {in} (1:{alias=ORPCTHIS}(struct))
	{
		if o.This == nil {
			o.This = &dcom.ORPCThis{}
		}
		if err := o.This.UnmarshalNDR(ctx, w); err != nil {
			return err
		}
		if err := w.ReadDeferred(); err != nil {
			return err
		}
	}
	// wszName {in} (1:{alias=LPCWSTR,pointer=ref}*(1)[dim:0,string](wchar))
	{
		if err := ndr.ReadUTF16String(ctx, w, &o.Name); err != nil {
			return err
		}
	}
	// lFlags {in} (1:(int32))
	{
		if err := w.ReadData(&o.Flags); err != nil {
			return err
		}
	}
	// pVal {in} (1:{pointer=ref}*(2))(2:{alias=VARIANT,pointer=ref}*(1))(3:{alias=_VARIANT}(struct))
	{
		_ptr_pVal := ndr.UnmarshalNDRFunc(func(ctx context.Context, w ndr.Reader) error {
			if o.Value == nil {
				o.Value = &oaut.Variant{}
			}
			if err := o.Value.UnmarshalNDR(ctx, w); err != nil {
				return err
			}
			return nil
		})
		_s_pVal := func(ptr interface{}) { o.Value = *ptr.(**oaut.Variant) }
		if err := w.ReadPointer(&o.Value, _s_pVal, _ptr_pVal); err != nil {
			return err
		}
		if err := w.ReadDeferred(); err != nil {
			return err
		}
	}
	// Type {in} (1:{alias=CIMTYPE}(enum))
	{
		if err := w.ReadEnum((*uint16)(&o.Type)); err != nil {
			return err
		}
	}
	return nil
}

func (o *xxx_PutOperation) xxx_PrepareResponsePayload(ctx context.Context) error {
	if hook, ok := (interface{})(o).(interface{ AfterPrepareResponsePayload(context.Context) error }); ok {
		if err := hook.AfterPrepareResponsePayload(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (o *xxx_PutOperation) MarshalNDRResponse(ctx context.Context, w ndr.Writer) error {
	if err := o.xxx_PrepareResponsePayload(ctx); err != nil {
		return err
	}
	// That {out} (1:{alias=ORPCTHAT}(struct))
	{
		if o.That != nil {
			if err := o.That.MarshalNDR(ctx, w); err != nil {
				return err
			}
		} else {
			if err := (&dcom.ORPCThat{}).MarshalNDR(ctx, w); err != nil {
				return err
			}
		}
		if err := w.WriteDeferred(); err != nil {
			return err
		}
	}
	// Return {out} (1:{alias=HRESULT}(int32))
	{
		if err := w.WriteData(o.Return); err != nil {
			return err
		}
	}
	return nil
}

func (o *xxx_PutOperation) UnmarshalNDRResponse(ctx context.Context, w ndr.Reader) error {
	// That {out} (1:{alias=ORPCTHAT}(struct))
	{
		if o.That == nil {
			o.That = &dcom.ORPCThat{}
		}
		if err := o.That.UnmarshalNDR(ctx, w); err != nil {
			return err
		}
		if err := w.ReadDeferred(); err != nil {
			return err
		}
	}
	// Return {out} (1:{alias=HRESULT}(int32))
	{
		if err := w.ReadData(&o.Return); err != nil {
			return err
		}
	}
	return nil
}

// PutRequest structure represents the Put operation request
type PutRequest struct {
	// This: ORPCTHIS structure that is used to send ORPC extension data to the server.
	This  *dcom.ORPCThis `idl:"name:This" json:"this"`
	Name  string         `idl:"name:wszName" json:"name"`
	Flags int32          `idl:"name:lFlags" json:"flags"`
	Value *oaut.Variant  `idl:"name:pVal" json:"value"`
	Type  wmi.Cimtype    `idl:"name:Type" json:"type"`
}

func (o *PutRequest) xxx_ToOp(ctx context.Context, op *xxx_PutOperation) *xxx_PutOperation {
	if op == nil {
		op = &xxx_PutOperation{}
	}
	if o == nil {
		return op
	}
	op.This = o.This
	op.Name = o.Name
	op.Flags = o.Flags
	op.Value = o.Value
	op.Type = o.Type
	return op
}

func (o *PutRequest) xxx_FromOp(ctx context.Context, op *xxx_PutOperation) {
	if o == nil {
		return
	}
	o.This = op.This
	o.Name = op.Name
	o.Flags = op.Flags
	o.Value = op.Value
	o.Type = op.Type
}
func (o *PutRequest) MarshalNDR(ctx context.Context, w ndr.Writer) error {
	return o.xxx_ToOp(ctx, nil).MarshalNDRRequest(ctx, w)
}
func (o *PutRequest) UnmarshalNDR(ctx context.Context, r ndr.Reader) error {
	_o := &xxx_PutOperation{}
	if err := _o.UnmarshalNDRRequest(ctx, r); err != nil {
		return err
	}
	o.xxx_FromOp(ctx, _o)
	return nil
}

// PutResponse structure represents the Put operation response
type PutResponse struct {
	// That: ORPCTHAT structure that is used to return ORPC extension data to the client.
	That *dcom.ORPCThat `idl:"name:That" json:"that"`
	// Return: The Put return value.
	Return int32 `idl:"name:Return" json:"return"`
}

func (o *PutResponse) xxx_ToOp(ctx context.Context, op *xxx_PutOperation) *xxx_PutOperation {
	if op == nil {
		op = &xxx_PutOperation{}
	}
	if o == nil {
		return op
	}
	op.That = o.That
	op.Return = o.Return
	return op
}

func (o *PutResponse) xxx_FromOp(ctx context.Context, op *xxx_PutOperation) {
	if o == nil {
		return
	}
	o.That = op.That
	o.Return = op.Return
}
func (o *PutResponse) MarshalNDR(ctx context.Context, w ndr.Writer) error {
	return o.xxx_ToOp(ctx, nil).MarshalNDRResponse(ctx, w)
}
func (o *PutResponse) UnmarshalNDR(ctx context.Context, r ndr.Reader) error {
	_o := &xxx_PutOperation{}
	if err := _o.UnmarshalNDRResponse(ctx, r); err != nil {
		return err
	}
	o.xxx_FromOp(ctx, _o)
	return nil
}
