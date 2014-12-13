// Copyright 2014 Google Inc. All Rights Reserved.
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

package google

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path"

	"github.com/proppy/oauth2"
)

const gcloudPath = ".config/gcloud/credentials"

// credentials stores gcloud credentials.
type credentials struct {
	Data []struct {
		Credential struct {
			ClientId     string `json:"Client_Id"`
			ClientSecret string `json:"Client_Secret"`
			RefreshToken string `json:"Refresh_Token"`
		}
		Key struct {
			Scope string
		}
		ProjectId string `json:"projectId"`
	}
}

// path returns gcloud credentials path.
func gcloudCredPath() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user")
	}
	return path.Join(usr.HomeDir, gcloudPath), nil
}

// NewTransportFromCredential return a oauth2.Transport from gcloud credentials.
func NewTransportFromCredentials() (*oauth2.Transport, error) {
	path, err := gcloudCredPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials path: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load credentials from %q: %v", path, err)
	}
	defer f.Close()

	var c credentials
	if err := json.NewDecoder(f).Decode(c); err != nil {
		return nil, fmt.Errorf("failed to decode credentials from %q: %v", path, err)
	}
	if len(c.Data) == 0 {
		return nil, fmt.Errorf("no credentials found in: %q", path)
	}
	return c.transport()
}

func (c *credentials) transport() (*oauth2.Transport, error) {
	authURL, _ := url.Parse("https://accounts.google.com/o/oauth2/auth")
	tokenURL, _ := url.Parse("https://accounts.google.com/o/oauth2/token")
	opts := &oauth2.Options{
		ClientID:     c.Data[0].Credential.ClientId,
		ClientSecret: c.Data[0].Credential.ClientSecret,
		Scopes:       []string{c.Data[0].Key.Scope},
		RedirectURL:  "oob",
		AuthURL:      authURL,
		TokenURL:     tokenURL,
	}
	t := opts.NewTransportFromToken(&oauth2.Token{RefreshToken: c.Data[0].Credential.RefreshToken})
	if err := t.Refresh(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %v", err)
	}
	return t, nil
}
