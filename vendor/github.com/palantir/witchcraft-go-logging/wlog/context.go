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

package wlog

import (
	"context"

	wloginternal "github.com/palantir/witchcraft-go-logging/wlog/internal"
)

func ContextWithUID(ctx context.Context, uid string) context.Context {
	return wloginternal.ContextWithID(ctx, wloginternal.UIDKey, uid)
}

func ContextWithSID(ctx context.Context, sid string) context.Context {
	return wloginternal.ContextWithID(ctx, wloginternal.SIDKey, sid)
}

func ContextWithTokenID(ctx context.Context, tokenID string) context.Context {
	return wloginternal.ContextWithID(ctx, wloginternal.TokenIDKey, tokenID)
}
