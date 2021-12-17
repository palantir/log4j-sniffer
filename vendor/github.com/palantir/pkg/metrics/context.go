// Copyright (c) 2018 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"context"
)

type mContextKey string

const (
	registryKey = mContextKey("metrics-registry")
	tagsKey     = mContextKey("metrics-tags")
)

var DefaultMetricsRegistry = NewRootMetricsRegistry()

func WithRegistry(ctx context.Context, registry Registry) context.Context {
	return context.WithValue(ctx, registryKey, registry)
}

func FromContext(ctx context.Context) Registry {
	registry, ok := ctx.Value(registryKey).(Registry)
	if !ok {
		registry = DefaultMetricsRegistry
	}
	rootRegistry, ok := registry.(*rootRegistry)
	if !ok {
		return registry
	}
	tagsContainer, ok := ctx.Value(tagsKey).(*tagsContainer)
	if !ok {
		return registry
	}
	return &childRegistry{
		root: rootRegistry,
		tags: tagsContainer.Tags,
	}
}

// AddTags adds the provided tags to the provided context. If no tags are provided, the context is returned unchanged.
// Otherwise, a new context is returned with the new tags appended to any tags stored on the parent context.
// This function does not perform any de-duplication (that is, if a tag in the provided tags has the
// same key as an existing one, it will still be appended).
func AddTags(ctx context.Context, tags ...Tag) context.Context {
	if len(tags) == 0 {
		return ctx
	}
	container, ok := ctx.Value(tagsKey).(*tagsContainer)
	if !ok || container == nil {
		container = &tagsContainer{}
	}
	return context.WithValue(ctx, tagsKey, &tagsContainer{
		Tags: append(container.Tags, tags...),
	})
}

// TagsFromContext returns the tags stored on the provided context. May be nil if no tags have been set on the context.
func TagsFromContext(ctx context.Context) Tags {
	if tagsContainer, ok := ctx.Value(tagsKey).(*tagsContainer); ok {
		return tagsContainer.Tags
	}
	return nil
}

type tagsContainer struct {
	Tags Tags
}
