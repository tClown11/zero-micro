package logic

import (
	"context"
	"errors"
	"strings"

	"github.com/tClown11/zero-micro/application/applet/internal/code"
	"github.com/tClown11/zero-micro/application/applet/internal/svc"
	"github.com/tClown11/zero-micro/application/applet/internal/types"
	"github.com/tClown11/zero-micro/application/user/rpc/user"
	"github.com/tClown11/zero-micro/pkg/encrypt"
	"github.com/tClown11/zero-micro/pkg/jwt"

	"github.com/zeromicro/go-zero/core/logx"
)

type RegisterLogic struct {
	logx.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewRegisterLogic(ctx context.Context, svcCtx *svc.ServiceContext) *RegisterLogic {
	return &RegisterLogic{
		Logger: logx.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *RegisterLogic) Register(req *types.RegisterRequest) (*types.RegisterResponse, error) {
	if err := checkRegisterRequest(l.svcCtx, req); err != nil {
		return nil, err
	}

	mobile, err := encrypt.EncMobile(req.Mobile)
	if err != nil {
		logx.Errorf("EncMobile mobile: %s error: %v", req.Mobile, err)
		return nil, err
	}
	u, err := l.svcCtx.UserRPC.FindByMobile(l.ctx, &user.FindByMobileRequest{
		Mobile: mobile,
	})
	if err != nil {
		logx.Errorf("FindByMobile error: %v", err)
		return nil, err
	}
	if u != nil && u.UserId > 0 {
		return nil, code.MobileHasRegistered
	}
	regRet, err := l.svcCtx.UserRPC.Register(l.ctx, &user.RegisterRequest{
		Username: req.Name,
		Mobile:   mobile,
	})
	if err != nil {
		logx.Errorf("Register error: %v", err)
		return nil, err
	}
	token, err := jwt.BuildTokens(jwt.TokenOptions{
		AccessSecret: l.svcCtx.Config.Auth.AccessSecret,
		AccessExpire: l.svcCtx.Config.Auth.AccessExpire,
		Fields: map[string]interface{}{
			"userId": regRet.UserId,
		},
	})
	if err != nil {
		logx.Errorf("BuildTokens error: %v", err)
		return nil, err
	}

	if err = delActivationCache(req.Mobile, l.svcCtx.BizRedis); err != nil {
		return nil, err
	}

	return &types.RegisterResponse{
		UserId: regRet.UserId,
		Token: types.Token{
			AccessToken:  token.AccessToken,
			AccessExpire: token.AccessExpire,
		},
	}, nil
}

func checkRegisterRequest(svcCtx *svc.ServiceContext, req *types.RegisterRequest) error {
	req.Name = strings.TrimSpace(req.Name)
	req.Mobile = strings.TrimSpace(req.Mobile)
	if len(req.Mobile) == 0 {
		return code.RegisterMobileEmpty
	}
	req.Password = strings.TrimSpace(req.Password)
	if len(req.Password) == 0 {
		return code.RegisterPasswdEmpty
	} else {
		req.Password = encrypt.EncPassword(req.Password)
	}
	req.VerificationCode = strings.TrimSpace(req.VerificationCode)
	if len(req.VerificationCode) == 0 {
		return code.VerificationCodeEmpty
	}
	err := checkVerificationCode(svcCtx, req.Mobile, req.VerificationCode)
	if err != nil {
		logx.Errorf("checkVerificationCode error: %v", err)
		return err
	}
	return nil
}

func checkVerificationCode(svcCtx *svc.ServiceContext, mobile, code string) error {
	cacheCode, err := getActivationCache(mobile, svcCtx.BizRedis)
	if err != nil {
		return err
	}
	if cacheCode == "" {
		return errors.New("verification code expired")
	}
	if cacheCode != code {
		return errors.New("verification code failed")
	}

	return nil
}
