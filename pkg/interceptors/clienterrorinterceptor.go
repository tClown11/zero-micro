package interceptors

import (
	"context"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/tClown11/zero-micro/pkg/xcode"
)

func ClientErrorInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		err := invoker(ctx, method, req, reply, cc, opts...)
		if err != nil {
			grpcStatus, _ := status.FromError(err)
			xc := xcode.GrpcStatusToXCode(grpcStatus)
			err = errors.WithMessage(xc, grpcStatus.Message())
		}
		return err
	}
}
