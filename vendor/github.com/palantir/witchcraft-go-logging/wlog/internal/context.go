// Copyright (c) 2018 Palantir Technologies. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wloginternal

import (
	"context"
)

type wlogContextKeyType string

const (
	UIDKey     = wlogContextKeyType("wlog.uid")
	SIDKey     = wlogContextKeyType("wlog.sid")
	TokenIDKey = wlogContextKeyType("wlog.tokenID")
)

func ContextWithID(ctx context.Context, key wlogContextKeyType, id string) context.Context {
	return context.WithValue(ctx, key, id)
}

func IDFromContext(ctx context.Context, key wlogContextKeyType) *string {
	if val, ok := ctx.Value(key).(string); ok {
		return &val
	}
	return nil
}
