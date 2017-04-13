//   Copyright 2017 Anatole Denis
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

// Package sap provides a parser and network utilities for SAP packages
package sap

import "time"

// ChannelFilter is the type of functions making a decision whether to report on a stream
type ChannelFilter func(*AdvLifetime) bool

// ChannelList filters SAP Announcements by channel name
func ChannelList(channels []string) ChannelFilter {
	return func(lf *AdvLifetime) bool {
		for _, c := range channels {
			if c == lf.Session {
				return true
			}
		}
		return false
	}
}

// FilterNotExpired is a channel filter function which only returns still-valid announcements wrt RFC2974
func FilterNotExpired(lf *AdvLifetime) bool {
	return lf.Last.Add(lf.Interval*10).After(time.Now()) || lf.Last.Add(time.Hour).After(time.Now())
}

// FilterAnd combines two ChannelFilter as a logical and
func FilterAnd(a, b ChannelFilter) ChannelFilter {
	return func(lf *AdvLifetime) bool {
		return a(lf) && b(lf)
	}
}
