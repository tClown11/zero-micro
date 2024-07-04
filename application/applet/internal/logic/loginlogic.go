package logic

import (
	"context"
	"strings"

	"github.com/tClown11/zero-micro/application/applet/internal/code"
	"github.com/tClown11/zero-micro/application/applet/internal/svc"
	"github.com/tClown11/zero-micro/application/applet/internal/types"
	"github.com/tClown11/zero-micro/application/user/rpc/user"
	"github.com/tClown11/zero-micro/pkg/encrypt"
	"github.com/tClown11/zero-micro/pkg/jwt"
	"github.com/tClown11/zero-micro/pkg/xcode"

	"github.com/zeromicro/go-zero/core/logx"
)

type LoginLogic struct {
	logx.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewLoginLogic(ctx context.Context, svcCtx *svc.ServiceContext) *LoginLogic {
	return &LoginLogic{
		Logger: logx.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *LoginLogic) Login(req *types.LoginRequest) (*types.LoginResponse, error) {
	// todo: add your logic here and delete this line
	if err := checkLoginRequest(l.svcCtx, req); err != nil {
		return nil, err
	}

	mobile, err := encrypt.EncMobile(req.Mobile)
	if err != nil {
		logx.Errorf("EncMobile mobile: %s error: %v", req.Mobile, err)
		return nil, err
	}
	u, err := l.svcCtx.UserRPC.FindByMobile(l.ctx, &user.FindByMobileRequest{Mobile: mobile})
	if err != nil {
		logx.Errorf("FindByMobile error: %v", err)
		return nil, err
	}
	if u == nil || u.UserId == 0 {
		return nil, xcode.AccessDenied
	}

	token, err := jwt.BuildTokens(jwt.TokenOptions{
		AccessSecret: l.svcCtx.Config.Auth.AccessSecret,
		AccessExpire: l.svcCtx.Config.Auth.AccessExpire,
		Fields: map[string]interface{}{
			"userId": u.UserId,
		},
	})
	if err != nil {
		return nil, err
	}

	if err := delActivationCache(req.Mobile, l.svcCtx.BizRedis); err != nil {
		return nil, err
	}

	return &types.LoginResponse{
		UserId: u.UserId,
		Token: types.Token{
			AccessToken:  token.AccessToken,
			AccessExpire: token.AccessExpire,
		},
	}, nil
}

func checkLoginRequest(svcCtx *svc.ServiceContext, req *types.LoginRequest) error {
	req.Mobile = strings.TrimSpace(req.Mobile)
	if len(req.Mobile) == 0 {
		return code.LoginMobileEmpty
	}
	req.VerificationCode = strings.TrimSpace(req.VerificationCode)
	if len(req.VerificationCode) == 0 {
		return code.VerificationCodeEmpty
	}
	err := checkVerificationCode(svcCtx, req.Mobile, req.VerificationCode)
	if err != nil {
		return err
	}
	return nil
}
