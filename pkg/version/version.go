// Copyright 2024 FootprintAI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package version

import (
	"fmt"
	"runtime/debug"

	goversion "github.com/hashicorp/go-version"
)

var (
	BuildTime  = ""
	version, _ = goversion.NewVersion("0.0.3")
)

func GreatThan(v1, v2 string) bool {
	v1v, _ := goversion.NewVersion(v1)
	v2v, _ := goversion.NewVersion(v2)

	return v1v.GreaterThan(v2v)
}

func GetVersion() string {
	return version.String()
}

func GetBuildTime() string {
	return BuildTime
}

func GetCommitHash() string {
	info, _ := debug.ReadBuildInfo()
	var rev string = "<none>"
	var dirty string = ""
	for _, v := range info.Settings {
		if v.Key == "vcs.revision" {
			rev = v.Value
		}
		if v.Key == "vcs.modified" {
			if v.Value == "true" {
				dirty = "-dirty"
			} else {
				dirty = ""
			}
		}
	}
	return rev + dirty
}

func Print() {
	fmt.Printf(`version:%s, build time:%s, hashid:%s\n`,
		GetVersion(),
		GetBuildTime(),
		GetCommitHash(),
	)

}
