// Copyright 2026 contributors to cbom-netscan
//
// SPDX-License-Identifier: Apache-2.0

//go:build race

package model

// raceEnabled is true under go test -race, which makes large tests much
// slower and hungrier for memory.
const raceEnabled = true
