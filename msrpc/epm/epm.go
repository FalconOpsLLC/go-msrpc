// The epm package implements the EPM client protocol.
package epm

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf16"

	dcerpc "github.com/FalconOpsLLC/go-msrpc/dcerpc"
	errors "github.com/FalconOpsLLC/go-msrpc/dcerpc/errors"
	uuid "github.com/FalconOpsLLC/go-msrpc/midl/uuid"
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
)

var (
	// import guard
	GoPackage = "epm"
)
