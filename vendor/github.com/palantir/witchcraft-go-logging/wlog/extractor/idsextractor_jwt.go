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

package extractor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	uuid "github.com/satori/go.uuid"
)

const (
	UIDKey     = "uid"
	SIDKey     = "sid"
	TokenIDKey = "tokenId"
)

// newIDsFromJWTExtractor creates an extractor that sets the UIDKey, SIDKey and TokenIDKey keys to have the values
// parsed from the JWT used as the bearer token in the "Authorization" header of the request. The JWT's "sub" field is
// used as the UID, the "sid" field is used as the SID and the "jti" field is used as the tokenID.
func newIDsFromJWTExtractor() IDsFromRequest {
	return &jwtRequestIDsExtractor{}
}

type jwtRequestIDsExtractor struct{}

func (e *jwtRequestIDsExtractor) ExtractIDs(req *http.Request) map[string]string {
	const bearerTokenPrefix = "Bearer "

	var uid, sid, tokenID string
	authContent := req.Header.Get("Authorization")
	if strings.HasPrefix(authContent, bearerTokenPrefix) {
		uid, sid, tokenID, _ = idsFromJWT(authContent[len(bearerTokenPrefix):])
	}
	return map[string]string{
		UIDKey:     uid,
		SIDKey:     sid,
		TokenIDKey: tokenID,
	}
}

// idsFromJWT returns the uid, sid and tokenID in the provided JWT. Note that signature verification is not performed on
// the JWT, so the returned values should not be considered secure or used for security purposes. However, the values
// are considered acceptable for use in logging.
func idsFromJWT(jwtContent string) (uid string, sid string, tokenID string, err error) {
	parts := strings.Split(jwtContent, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("JWT must have 3 '.'-separated parts, but had %d: %q", len(parts), jwtContent)
	}
	bytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", "", fmt.Errorf("failed to decode JWT content %q as Base64 URL-encoded string: %v", parts[1], err)
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal(bytes, &jsonMap); err != nil {
		return "", "", "", fmt.Errorf("failed to decode JWT content %s as JSON: %v", string(bytes), err)
	}

	// "sub" = "subject" field, which is used as the UID
	uid = getMapUUIDStringVal(jsonMap, "sub")
	// "sid" is used to store the session ID
	sid = getMapUUIDStringVal(jsonMap, "sid")
	// "jti" is used to store the token ID
	tokenID = getMapUUIDStringVal(jsonMap, "jti")

	return uid, sid, tokenID, nil
}

func getMapUUIDStringVal(m map[string]interface{}, key string) string {
	val, ok := m[key]
	if !ok {
		return ""
	}
	str, ok := val.(string)
	if !ok {
		return ""
	}

	rawBytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		// if string was not Base64-encoded, return original raw string
		return str
	}

	id, err := uuid.FromBytes(rawBytes)
	if err != nil {
		// if Base64-decoded bytes did not represent a UUID, return original raw string
		return str
	}

	// success: return string representation of UUID
	return id.String()
}
