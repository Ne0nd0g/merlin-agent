// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package opaque

import (
	// Standard
	"crypto/sha256"
	"fmt"

	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/pbkdf2"

	// Merlin Main
	"github.com/Ne0nd0g/merlin/pkg/opaque"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/core"
)

// User is the structure that holds information for the various steps of the OPAQUE protocol as the user
type User struct {
	reg         *gopaque.UserRegister         // User Registration
	regComplete *gopaque.UserRegisterComplete // User Registration Complete
	auth        *gopaque.UserAuth             // User Authentication
	Kex         *gopaque.KeyExchangeSigma     // User Key Exchange
	pwdU        []byte                        // User Password
}

// UserRegisterInit is used to perform the OPAQUE Password Authenticated Key Exchange (PAKE) protocol Registration steps for the user
func UserRegisterInit(AgentID uuid.UUID) (opaque.Opaque, *User, error) {
	cli.Message(cli.DEBUG, "Entering into opaque.UserRegisterInit...")
	var user User
	// Generate a random password and run it through 5000 iterations of PBKDF2; Used with OPAQUE
	x := core.RandStringBytesMaskImprSrc(30)
	user.pwdU = pbkdf2.Key([]byte(x), AgentID.Bytes(), 5000, 32, sha256.New)

	// Build OPAQUE User Registration Initialization
	user.reg = gopaque.NewUserRegister(gopaque.CryptoDefault, AgentID.Bytes(), nil)
	userRegInit := user.reg.Init(user.pwdU)

	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE UserID: %x", userRegInit.UserID))
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE Alpha: %v", userRegInit.Alpha))
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE PwdU: %x", user.pwdU))

	userRegInitBytes, errUserRegInitBytes := userRegInit.ToBytes()
	if errUserRegInitBytes != nil {
		return opaque.Opaque{}, &user, fmt.Errorf("there was an error marshalling the OPAQUE user registration initialization message to bytes:\r\n%s", errUserRegInitBytes.Error())
	}

	// Message to be sent to the server
	regInit := opaque.Opaque{
		Type:    opaque.RegInit,
		Payload: userRegInitBytes,
	}

	return regInit, &user, nil
}

// UserRegisterComplete consumes the Server's response and finishes OPAQUE registration
func UserRegisterComplete(regInitResp opaque.Opaque, user *User) (opaque.Opaque, error) {
	cli.Message(cli.DEBUG, "Entering into opaque.UserRegisterComplete...")

	if regInitResp.Type != opaque.RegInit {
		return opaque.Opaque{}, fmt.Errorf("expected OPAQUE message type %d, got %d", opaque.RegInit, regInitResp.Type)
	}

	// Check to see if OPAQUE User Registration was previously completed
	if user.regComplete == nil {
		var serverRegInit gopaque.ServerRegisterInit

		errServerRegInit := serverRegInit.FromBytes(gopaque.CryptoDefault, regInitResp.Payload)
		if errServerRegInit != nil {
			return opaque.Opaque{}, fmt.Errorf("there was an error unmarshalling the OPAQUE server register initialization message from bytes:\r\n%s", errServerRegInit.Error())
		}

		cli.Message(cli.NOTE, "Received OPAQUE server registration initialization message")
		cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE Beta: %v", serverRegInit.Beta))
		cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE V: %v", serverRegInit.V))
		cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE PubS: %s", serverRegInit.ServerPublicKey))

		// TODO extend gopaque to run RwdU through n iterations of PBKDF2
		user.regComplete = user.reg.Complete(&serverRegInit)
	}

	userRegCompleteBytes, errUserRegCompleteBytes := user.regComplete.ToBytes()
	if errUserRegCompleteBytes != nil {
		return opaque.Opaque{}, fmt.Errorf("there was an error marshalling the OPAQUE user registration complete message to bytes:\r\n%s", errUserRegCompleteBytes.Error())
	}

	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE EnvU: %x", user.regComplete.EnvU))
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE PubU: %v", user.regComplete.UserPublicKey))

	// message to be sent to the server
	regComplete := opaque.Opaque{
		Type:    opaque.RegComplete,
		Payload: userRegCompleteBytes,
	}

	return regComplete, nil
}

// UserAuthenticateInit is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func UserAuthenticateInit(AgentID uuid.UUID, user *User) (opaque.Opaque, error) {
	cli.Message(cli.DEBUG, "Entering into opaque.UserAuthenticateInit...")

	// 1 - Create a NewUserAuth with an embedded key exchange
	user.Kex = gopaque.NewKeyExchangeSigma(gopaque.CryptoDefault)
	user.auth = gopaque.NewUserAuth(gopaque.CryptoDefault, AgentID.Bytes(), user.Kex)

	// 2 - Call Init with the password and send the resulting UserAuthInit to the server
	userAuthInit, err := user.auth.Init(user.pwdU)
	if err != nil {
		return opaque.Opaque{}, fmt.Errorf("there was an error creating the OPAQUE user authentication initialization message:\r\n%s", err.Error())
	}

	userAuthInitBytes, errUserAuthInitBytes := userAuthInit.ToBytes()
	if errUserAuthInitBytes != nil {
		return opaque.Opaque{}, fmt.Errorf("there was an error marshalling the OPAQUE user authentication initialization message to bytes:\r\n%s", errUserAuthInitBytes.Error())
	}

	// message to be sent to the server
	authInit := opaque.Opaque{
		Type:    opaque.AuthInit,
		Payload: userAuthInitBytes,
	}

	return authInit, nil
}

// UserAuthenticateComplete consumes the Server's authentication message and finishes the user authentication and key exchange
func UserAuthenticateComplete(authInitResp opaque.Opaque, user *User) (opaque.Opaque, error) {
	cli.Message(cli.DEBUG, "Entering into opaque.UserAuthenticateComplete...")

	if authInitResp.Type != opaque.AuthInit {
		return opaque.Opaque{}, fmt.Errorf("expected OPAQUE message type: %d, recieved: %d", opaque.AuthInit, authInitResp.Type)
	}

	// 3 - Receive the server's ServerAuthComplete
	var serverComplete gopaque.ServerAuthComplete

	errServerComplete := serverComplete.FromBytes(gopaque.CryptoDefault, authInitResp.Payload)
	if errServerComplete != nil {
		return opaque.Opaque{}, fmt.Errorf("there was an error unmarshalling the OPAQUE server complete message from bytes:\r\n%s", errServerComplete.Error())
	}

	// 4 - Call Complete with the server's ServerAuthComplete. The resulting UserAuthFinish has user and server key
	// information. This would be the last step if we were not using an embedded key exchange. Since we are, take the
	// resulting UserAuthComplete and send it to the server.
	cli.Message(cli.NOTE, "Received OPAQUE server complete message")
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE Beta: %x", serverComplete.Beta))
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE V: %x", serverComplete.V))
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE PubS: %x", serverComplete.ServerPublicKey))
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE EnvU: %x", serverComplete.EnvU))

	_, userAuthComplete, errUserAuth := user.auth.Complete(&serverComplete)
	if errUserAuth != nil {
		return opaque.Opaque{}, fmt.Errorf("there was an error completing OPAQUE authentication:\r\n%s", errUserAuth)
	}

	userAuthCompleteBytes, errUserAuthCompleteBytes := userAuthComplete.ToBytes()
	if errUserAuthCompleteBytes != nil {
		return opaque.Opaque{}, fmt.Errorf("there was an error marshalling the OPAQUE user authentication complete message to bytes:\r\n%s", errUserAuthCompleteBytes.Error())
	}

	authComplete := opaque.Opaque{
		Type:    opaque.AuthComplete,
		Payload: userAuthCompleteBytes,
	}

	return authComplete, nil
}
