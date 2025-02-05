package logic

import (
	"context"
	"encoding/json"

	"github.com/tClown11/zero-micro/application/applet/internal/svc"
	"github.com/tClown11/zero-micro/application/applet/internal/types"
	"github.com/tClown11/zero-micro/application/user/rpc/user"

	"github.com/zeromicro/go-zero/core/logx"
)

type UserInfoLogic struct {
	logx.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewUserInfoLogic(ctx context.Context, svcCtx *svc.ServiceContext) *UserInfoLogic {
	return &UserInfoLogic{
		Logger: logx.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

// UserInfo: get user info when is exist that return it
func (l *UserInfoLogic) UserInfo() (*types.UserInfoResponse, error) {
	userId, err := l.ctx.Value(types.UserIdKey).(json.Number).Int64()
	if err != nil {
		return nil, err
	}
	if userId == 0 {
		return &types.UserInfoResponse{}, nil
	}

	u, err := l.svcCtx.UserRPC.FindById(l.ctx, &user.FindByIdRequest{
		UserId: userId,
	})
	if err != nil {
		logx.Errorf("FindById userId: %d error: %v", userId, err)
		return nil, err
	}

	return &types.UserInfoResponse{
		UserId:   u.UserId,
		Username: u.Username,
		Avatar:   u.Avatar,
	}, nil
}
