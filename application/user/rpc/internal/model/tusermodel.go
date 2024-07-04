package model

import (
	"github.com/zeromicro/go-zero/core/stores/cache"
	"github.com/zeromicro/go-zero/core/stores/sqlx"
)

var _ TUserModel = (*customTUserModel)(nil)

type (
	// TUserModel is an interface to be customized, add more methods here,
	// and implement the added methods in customTUserModel.
	TUserModel interface {
		tUserModel
	}

	customTUserModel struct {
		*defaultTUserModel
	}
)

// NewTUserModel returns a model for the database table.
func NewTUserModel(conn sqlx.SqlConn, c cache.CacheConf, opts ...cache.Option) TUserModel {
	return &customTUserModel{
		defaultTUserModel: newTUserModel(conn, c, opts...),
	}
}
