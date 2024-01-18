// Copyright 2018 The goftp Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import "os"

// Perm represents a perm interface
type Perm interface {
	GetOwner(*Context, string) (string, error)
	GetGroup(*Context, string) (string, error)
	GetMode(*Context, string) (os.FileMode, error)

	ChOwner(*Context, string, string) error
	ChGroup(*Context, string, string) error
	ChMode(*Context, string, os.FileMode) error
}

// SimplePerm implements Perm interface that all files are owned by special owner and group
type SimplePerm struct {
	owner, group string
}

// NewSimplePerm creates a SimplePerm
func NewSimplePerm(owner, group string) *SimplePerm {
	return &SimplePerm{
		owner: owner,
		group: group,
	}
}

// GetOwner returns the file's owner
func (s *SimplePerm) GetOwner(ctx *Context, path string) (string, error) {
	return s.owner, nil
}

// GetGroup returns the group of the file
func (s *SimplePerm) GetGroup(ctx *Context, path string) (string, error) {
	return s.group, nil
}

// GetMode returns the file's mode
func (s *SimplePerm) GetMode(ctx *Context, path string) (os.FileMode, error) {
	return os.ModePerm, nil
}

// ChOwner changed the file's owner
func (s *SimplePerm) ChOwner(ctx *Context, path string, owner string) error {
	return nil
}

// ChGroup changed the file's group
func (s *SimplePerm) ChGroup(ctx *Context, path string, group string) error {
	return nil
}

// ChMode changed the file's mode
func (s *SimplePerm) ChMode(ctx *Context, path string, mode os.FileMode) error {
	return nil
}
