// Copyright (c) 2021 Palantir Technologies. All rights reserved.
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

package docker

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/api/types/volume"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

type mockDockerClient struct {
	imageFile    string
	imageSummary types.ImageSummary
}

func (m mockDockerClient) ImageList(ctx context.Context, options types.ImageListOptions) ([]types.ImageSummary, error) {
	return []types.ImageSummary{m.imageSummary}, nil
}

func (m mockDockerClient) ImageSave(ctx context.Context, images []string) (io.ReadCloser, error) {
	return os.Open(m.imageFile)
}

func (m mockDockerClient) NegotiateAPIVersion(ctx context.Context) {
	return
}

func (m mockDockerClient) ConfigList(ctx context.Context, options types.ConfigListOptions) ([]swarm.Config, error) {
	panic("not implemented")
}

func (m mockDockerClient) ConfigCreate(ctx context.Context, config swarm.ConfigSpec) (types.ConfigCreateResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) ConfigRemove(ctx context.Context, id string) error {
	panic("not implemented")
}

func (m mockDockerClient) ConfigInspectWithRaw(ctx context.Context, name string) (swarm.Config, []byte, error) {
	panic("not implemented")
}

func (m mockDockerClient) ConfigUpdate(ctx context.Context, id string, version swarm.Version, config swarm.ConfigSpec) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainerAttach(ctx context.Context, container string, options types.ContainerAttachOptions) (types.HijackedResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerCommit(ctx context.Context, container string, options types.ContainerCommitOptions) (types.IDResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, platform *v1.Platform, containerName string) (container.ContainerCreateCreatedBody, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerDiff(ctx context.Context, container string) ([]container.ContainerChangeResponseItem, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerExecAttach(ctx context.Context, execID string, config types.ExecStartCheck) (types.HijackedResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerExecCreate(ctx context.Context, container string, config types.ExecConfig) (types.IDResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerExecInspect(ctx context.Context, execID string) (types.ContainerExecInspect, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerExecResize(ctx context.Context, execID string, options types.ResizeOptions) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainerExecStart(ctx context.Context, execID string, config types.ExecStartCheck) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainerExport(ctx context.Context, container string) (io.ReadCloser, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerInspect(ctx context.Context, container string) (types.ContainerJSON, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerInspectWithRaw(ctx context.Context, container string, getSize bool) (types.ContainerJSON, []byte, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerKill(ctx context.Context, container, signal string) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerLogs(ctx context.Context, container string, options types.ContainerLogsOptions) (io.ReadCloser, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerPause(ctx context.Context, container string) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainerRemove(ctx context.Context, container string, options types.ContainerRemoveOptions) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainerRename(ctx context.Context, container, newContainerName string) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainerResize(ctx context.Context, container string, options types.ResizeOptions) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainerRestart(ctx context.Context, container string, timeout *time.Duration) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainerStatPath(ctx context.Context, container, path string) (types.ContainerPathStat, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerStats(ctx context.Context, container string, stream bool) (types.ContainerStats, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerStatsOneShot(ctx context.Context, container string) (types.ContainerStats, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerStart(ctx context.Context, container string, options types.ContainerStartOptions) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainerStop(ctx context.Context, container string, timeout *time.Duration) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainerTop(ctx context.Context, container string, arguments []string) (container.ContainerTopOKBody, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerUnpause(ctx context.Context, container string) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainerUpdate(ctx context.Context, container string, updateConfig container.UpdateConfig) (container.ContainerUpdateOKBody, error) {
	panic("not implemented")
}

func (m mockDockerClient) ContainerWait(ctx context.Context, container string, condition container.WaitCondition) (<-chan container.ContainerWaitOKBody, <-chan error) {
	panic("not implemented")
}

func (m mockDockerClient) CopyFromContainer(ctx context.Context, container, srcPath string) (io.ReadCloser, types.ContainerPathStat, error) {
	panic("not implemented")
}

func (m mockDockerClient) CopyToContainer(ctx context.Context, container, path string, content io.Reader, options types.CopyToContainerOptions) error {
	panic("not implemented")
}

func (m mockDockerClient) ContainersPrune(ctx context.Context, pruneFilters filters.Args) (types.ContainersPruneReport, error) {
	panic("not implemented")
}

func (m mockDockerClient) DistributionInspect(ctx context.Context, image, encodedRegistryAuth string) (registry.DistributionInspect, error) {
	panic("not implemented")
}

func (m mockDockerClient) ImageBuild(ctx context.Context, context io.Reader, options types.ImageBuildOptions) (types.ImageBuildResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) BuildCachePrune(ctx context.Context, opts types.BuildCachePruneOptions) (*types.BuildCachePruneReport, error) {
	panic("not implemented")
}

func (m mockDockerClient) BuildCancel(ctx context.Context, id string) error {
	panic("not implemented")
}

func (m mockDockerClient) ImageCreate(ctx context.Context, parentReference string, options types.ImageCreateOptions) (io.ReadCloser, error) {
	panic("not implemented")
}

func (m mockDockerClient) ImageHistory(ctx context.Context, image string) ([]image.HistoryResponseItem, error) {
	panic("not implemented")
}

func (m mockDockerClient) ImageImport(ctx context.Context, source types.ImageImportSource, ref string, options types.ImageImportOptions) (io.ReadCloser, error) {
	panic("not implemented")
}

func (m mockDockerClient) ImageInspectWithRaw(ctx context.Context, image string) (types.ImageInspect, []byte, error) {
	panic("not implemented")
}

func (m mockDockerClient) ImageLoad(ctx context.Context, input io.Reader, quiet bool) (types.ImageLoadResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) ImagePull(ctx context.Context, ref string, options types.ImagePullOptions) (io.ReadCloser, error) {
	panic("not implemented")
}

func (m mockDockerClient) ImagePush(ctx context.Context, ref string, options types.ImagePushOptions) (io.ReadCloser, error) {
	panic("not implemented")
}

func (m mockDockerClient) ImageRemove(ctx context.Context, image string, options types.ImageRemoveOptions) ([]types.ImageDeleteResponseItem, error) {
	panic("not implemented")
}

func (m mockDockerClient) ImageSearch(ctx context.Context, term string, options types.ImageSearchOptions) ([]registry.SearchResult, error) {
	panic("not implemented")
}

func (m mockDockerClient) ImageTag(ctx context.Context, image, ref string) error {
	panic("not implemented")
}

func (m mockDockerClient) ImagesPrune(ctx context.Context, pruneFilter filters.Args) (types.ImagesPruneReport, error) {
	panic("not implemented")
}

func (m mockDockerClient) NodeInspectWithRaw(ctx context.Context, nodeID string) (swarm.Node, []byte, error) {
	panic("not implemented")
}

func (m mockDockerClient) NodeList(ctx context.Context, options types.NodeListOptions) ([]swarm.Node, error) {
	panic("not implemented")
}

func (m mockDockerClient) NodeRemove(ctx context.Context, nodeID string, options types.NodeRemoveOptions) error {
	panic("not implemented")
}

func (m mockDockerClient) NodeUpdate(ctx context.Context, nodeID string, version swarm.Version, node swarm.NodeSpec) error {
	panic("not implemented")
}

func (m mockDockerClient) NetworkConnect(ctx context.Context, network, container string, config *network.EndpointSettings) error {
	panic("not implemented")
}

func (m mockDockerClient) NetworkCreate(ctx context.Context, name string, options types.NetworkCreate) (types.NetworkCreateResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) NetworkDisconnect(ctx context.Context, network, container string, force bool) error {
	panic("not implemented")
}

func (m mockDockerClient) NetworkInspect(ctx context.Context, network string, options types.NetworkInspectOptions) (types.NetworkResource, error) {
	panic("not implemented")
}

func (m mockDockerClient) NetworkInspectWithRaw(ctx context.Context, network string, options types.NetworkInspectOptions) (types.NetworkResource, []byte, error) {
	panic("not implemented")
}

func (m mockDockerClient) NetworkList(ctx context.Context, options types.NetworkListOptions) ([]types.NetworkResource, error) {
	panic("not implemented")
}

func (m mockDockerClient) NetworkRemove(ctx context.Context, network string) error {
	panic("not implemented")
}

func (m mockDockerClient) NetworksPrune(ctx context.Context, pruneFilter filters.Args) (types.NetworksPruneReport, error) {
	panic("not implemented")
}

func (m mockDockerClient) PluginList(ctx context.Context, filter filters.Args) (types.PluginsListResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) PluginRemove(ctx context.Context, name string, options types.PluginRemoveOptions) error {
	panic("not implemented")
}

func (m mockDockerClient) PluginEnable(ctx context.Context, name string, options types.PluginEnableOptions) error {
	panic("not implemented")
}

func (m mockDockerClient) PluginDisable(ctx context.Context, name string, options types.PluginDisableOptions) error {
	panic("not implemented")
}

func (m mockDockerClient) PluginInstall(ctx context.Context, name string, options types.PluginInstallOptions) (io.ReadCloser, error) {
	panic("not implemented")
}

func (m mockDockerClient) PluginUpgrade(ctx context.Context, name string, options types.PluginInstallOptions) (io.ReadCloser, error) {
	panic("not implemented")
}

func (m mockDockerClient) PluginPush(ctx context.Context, name string, registryAuth string) (io.ReadCloser, error) {
	panic("not implemented")
}

func (m mockDockerClient) PluginSet(ctx context.Context, name string, args []string) error {
	panic("not implemented")
}

func (m mockDockerClient) PluginInspectWithRaw(ctx context.Context, name string) (*types.Plugin, []byte, error) {
	panic("not implemented")
}

func (m mockDockerClient) PluginCreate(ctx context.Context, createContext io.Reader, options types.PluginCreateOptions) error {
	panic("not implemented")
}

func (m mockDockerClient) ServiceCreate(ctx context.Context, service swarm.ServiceSpec, options types.ServiceCreateOptions) (types.ServiceCreateResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) ServiceInspectWithRaw(ctx context.Context, serviceID string, options types.ServiceInspectOptions) (swarm.Service, []byte, error) {
	panic("not implemented")
}

func (m mockDockerClient) ServiceList(ctx context.Context, options types.ServiceListOptions) ([]swarm.Service, error) {
	panic("not implemented")
}

func (m mockDockerClient) ServiceRemove(ctx context.Context, serviceID string) error {
	panic("not implemented")
}

func (m mockDockerClient) ServiceUpdate(ctx context.Context, serviceID string, version swarm.Version, service swarm.ServiceSpec, options types.ServiceUpdateOptions) (types.ServiceUpdateResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) ServiceLogs(ctx context.Context, serviceID string, options types.ContainerLogsOptions) (io.ReadCloser, error) {
	panic("not implemented")
}

func (m mockDockerClient) TaskLogs(ctx context.Context, taskID string, options types.ContainerLogsOptions) (io.ReadCloser, error) {
	panic("not implemented")
}

func (m mockDockerClient) TaskInspectWithRaw(ctx context.Context, taskID string) (swarm.Task, []byte, error) {
	panic("not implemented")
}

func (m mockDockerClient) TaskList(ctx context.Context, options types.TaskListOptions) ([]swarm.Task, error) {
	panic("not implemented")
}

func (m mockDockerClient) SwarmInit(ctx context.Context, req swarm.InitRequest) (string, error) {
	panic("not implemented")
}

func (m mockDockerClient) SwarmJoin(ctx context.Context, req swarm.JoinRequest) error {
	panic("not implemented")
}

func (m mockDockerClient) SwarmGetUnlockKey(ctx context.Context) (types.SwarmUnlockKeyResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) SwarmUnlock(ctx context.Context, req swarm.UnlockRequest) error {
	panic("not implemented")
}

func (m mockDockerClient) SwarmLeave(ctx context.Context, force bool) error {
	panic("not implemented")
}

func (m mockDockerClient) SwarmInspect(ctx context.Context) (swarm.Swarm, error) {
	panic("not implemented")
}

func (m mockDockerClient) SwarmUpdate(ctx context.Context, version swarm.Version, swarm swarm.Spec, flags swarm.UpdateFlags) error {
	panic("not implemented")
}

func (m mockDockerClient) SecretList(ctx context.Context, options types.SecretListOptions) ([]swarm.Secret, error) {
	panic("not implemented")
}

func (m mockDockerClient) SecretCreate(ctx context.Context, secret swarm.SecretSpec) (types.SecretCreateResponse, error) {
	panic("not implemented")
}

func (m mockDockerClient) SecretRemove(ctx context.Context, id string) error {
	panic("not implemented")
}

func (m mockDockerClient) SecretInspectWithRaw(ctx context.Context, name string) (swarm.Secret, []byte, error) {
	panic("not implemented")
}

func (m mockDockerClient) SecretUpdate(ctx context.Context, id string, version swarm.Version, secret swarm.SecretSpec) error {
	panic("not implemented")
}

func (m mockDockerClient) Events(ctx context.Context, options types.EventsOptions) (<-chan events.Message, <-chan error) {
	panic("not implemented")
}

func (m mockDockerClient) Info(ctx context.Context) (types.Info, error) {
	panic("not implemented")
}

func (m mockDockerClient) RegistryLogin(ctx context.Context, auth types.AuthConfig) (registry.AuthenticateOKBody, error) {
	panic("not implemented")
}

func (m mockDockerClient) DiskUsage(ctx context.Context) (types.DiskUsage, error) {
	panic("not implemented")
}

func (m mockDockerClient) Ping(ctx context.Context) (types.Ping, error) {
	panic("not implemented")
}

func (m mockDockerClient) VolumeCreate(ctx context.Context, options volume.VolumeCreateBody) (types.Volume, error) {
	panic("not implemented")
}

func (m mockDockerClient) VolumeInspect(ctx context.Context, volumeID string) (types.Volume, error) {
	panic("not implemented")
}

func (m mockDockerClient) VolumeInspectWithRaw(ctx context.Context, volumeID string) (types.Volume, []byte, error) {
	panic("not implemented")
}

func (m mockDockerClient) VolumeList(ctx context.Context, filter filters.Args) (volume.VolumeListOKBody, error) {
	panic("not implemented")
}

func (m mockDockerClient) VolumeRemove(ctx context.Context, volumeID string, force bool) error {
	panic("not implemented")
}

func (m mockDockerClient) VolumesPrune(ctx context.Context, pruneFilter filters.Args) (types.VolumesPruneReport, error) {
	panic("not implemented")
}

func (m mockDockerClient) ClientVersion() string {
	panic("not implemented")
}

func (m mockDockerClient) DaemonHost() string {
	panic("not implemented")
}

func (m mockDockerClient) HTTPClient() *http.Client {
	panic("not implemented")
}

func (m mockDockerClient) ServerVersion(ctx context.Context) (types.Version, error) {
	panic("not implemented")
}

func (m mockDockerClient) NegotiateAPIVersionPing(ping types.Ping) {
	panic("not implemented")
}

func (m mockDockerClient) DialHijack(ctx context.Context, url, proto string, meta map[string][]string) (net.Conn, error) {
	panic("not implemented")
}

func (m mockDockerClient) Dialer() func(context.Context) (net.Conn, error) {
	panic("not implemented")
}

func (m mockDockerClient) Close() error {
	panic("not implemented")
}
