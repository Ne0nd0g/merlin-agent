//go:build mythic

/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package mythic

import (
	"github.com/google/uuid"
)

const (
	// CHECKIN is Mythic action https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/initial-checkin
	CHECKIN = "checkin"
	// TASKING is a Mythic action https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action_get_tasking
	TASKING = "get_tasking"
	// RESPONSE is used to send a message back to the Mythic server https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-post_response
	RESPONSE = "post_response"
	// StatusError is used to when there is an error
	StatusError = "error"
	// RSAStaging is used to setup and complete the RSA key exchange https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/initial-checkin
	RSAStaging = "staging_rsa"
	// UPLOAD is a Mythic action https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-upload
	UPLOAD = "upload"

	// Custom

	// DownloadInit is used as the first download message from the Mythic server
	DownloadInit = 300
	// DownloadSend is used after the init message to send the file
	DownloadSend = 301
)

// CheckIn is the initial structure sent to Mythic
type CheckIn struct {
	Action        string `json:"action"`                    // "action": "checkin", // required
	IP            string `json:"ip"`                        // "ip": "127.0.0.1", // internal ip address - required
	OS            string `json:"os"`                        // "os": "macOS 10.15", // os version - required
	User          string `json:"user"`                      // "user": "its-a-feature", // username of current user - required
	Host          string `json:"host"`                      // "host": "spooky.local", // hostname of the computer - required
	PID           int    `json:"pid"`                       // "pid": 4444, // pid of the current process - required
	PayloadID     string `json:"uuid"`                      // "uuid": "payload uuid", //uuid of the payload - required
	Arch          string `json:"architecture,omitempty"`    //  "architecture": "x64", // platform arch - optional
	Domain        string `json:"domain,omitempty"`          // "domain": "test", // domain of the host - optional
	Integrity     int    `json:"integrity_level,omitempty"` // "integrity_level": 3, // integrity level of the process - optional
	ExternalIP    string `json:"external_ip,omitempty"`     // "external_ip": "8.8.8.8", // external ip if known - optional
	EncryptionKey string `json:"encryption_key,omitempty"`  // "encryption_key": "base64 of key", // encryption key - optional
	DecryptionKey string `json:"decryption_key,omitempty"`  //  "decryption_key": "base64 of key", // decryption key - optional
	Process       string `json:"process_name,omitempty"`    // "process": "process name", // name of the process - optional
	Padding       string `json:"padding,omitempty"`
}

// Response is the message structure returned from the Mythic server
type Response struct {
	Action string `json:"action"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

// Error message returned from Mythic HTTP profile
type Error struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

// Tasking is used by the agent to request a specified number of tasks from the server
type Tasking struct {
	Action  string `json:"action"`
	Size    int    `json:"tasking_size"`
	Padding string `json:"padding,omitempty"`
}

// Tasks holds a list of tasks for the agent to process
type Tasks struct {
	Action string  `json:"action"`
	Tasks  []Task  `json:"tasks"`
	SOCKS  []Socks `json:"socks,omitempty"`
}

// Task contains the task identifier, command, and parameters for the agent to execute
type Task struct {
	ID      string  `json:"id"`
	Command string  `json:"command"`
	Params  string  `json:"parameters"`
	Time    float64 `json:"timestamp"`
}

// Job structure
type Job struct {
	Type    int    `json:"type"`
	Payload string `json:"payload"`
}

// PostResponse is the structure used to send a list of messages from the agent to the server
type PostResponse struct {
	Action    string               `json:"action"`
	Responses []ClientTaskResponse `json:"responses"` // TODO This needs to be an interface so it can handle both ClientTaskResponse and FileDownloadInitialMessage
	Padding   string               `json:"padding,omitempty"`
	SOCKS     []Socks              `json:"socks,omitempty"`
}

// ClientTaskResponse is the structure used to return the results of a task to the Mythic server
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-post_response
type ClientTaskResponse struct {
	ID        uuid.UUID     `json:"task_id"`
	Download  *FileDownload `json:"download,omitempty"`
	Output    string        `json:"user_output,omitempty"`
	Status    string        `json:"status,omitempty"`
	Completed bool          `json:"completed,omitempty"`
}

// ServerTaskResponse is the message Mythic returns to the client after it sent a ClientTaskResponse message
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-post_response
type ServerTaskResponse struct {
	ID     string `json:"task_id"`
	Status string `json:"status"`
	Error  string `json:"error"`
	FileID string `json:"file_id,omitempty"`
}

// ServerPostResponse structure holds a list of ServerTaskResponse structure
type ServerPostResponse struct {
	Action    string               `json:"action"`
	Responses []ServerTaskResponse `json:"responses"`
	SOCKS     []Socks              `json:"socks,omitempty"`
}

// PostResponseFile is the structure used to send a list of messages from the agent to the server
type PostResponseFile struct {
	Action    string         `json:"action"`
	Responses []FileDownload `json:"responses"`
	Padding   string         `json:"padding,omitempty"`
}

// FileDownloadInitialMessage contains the information for the initial step of the file download process
type FileDownloadInitialMessage struct {
	NumChunks    int    `json:"total_chunks"`
	TaskID       string `json:"task_id"`
	FullPath     string `json:"full_path"`
	IsScreenshot bool   `json:"is_screenshot"`
}

// PostResponseDownload is used to send a response to the Mythic server
type PostResponseDownload struct {
	Action    string         `json:"action"`
	Responses []FileDownload `json:"responses"`
	Padding   string         `json:"padding,omitempty"`
}

// FileDownload sends a chunk of Base64 encoded data from the agent to the server
type FileDownload struct {
	FileID       string `json:"file_id,omitempty"` // UUID from FileDownloadResponse
	NumChunks    int    `json:"total_chunks,omitempty"`
	Chunk        int    `json:"chunk_num,omitempty"`
	Data         string `json:"chunk_data,omitempty"` // Base64 encoded data
	FullPath     string `json:"full_path,omitempty"`
	IsScreenshot bool   `json:"is_screenshot,omitempty"`
}

// DownloadResponse is the server's response to a FileDownload message
type DownloadResponse struct {
	Status string `json:"status"`
	TaskID string `json:"task_id"`
}

// UploadRequest is message
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-upload
type UploadRequest struct {
	Action string `json:"action"`
	TaskID string `json:"task_id"`    // the associated task that caused the agent to pull down this file
	FileID string `json:"file_id"`    // the file specified to pull down to the target
	Path   string `json:"full_path"`  // ull path to uploaded file on Agent's host
	Size   int    `json:"chunk_size"` // bytes of file per chunk
	Chunk  int    `json:"chunk_num"`  // which chunk are we currently pulling down
}

// UploadResponse is the message sent from the server to an agent
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-upload
type UploadResponse struct {
	Path   string `json:"remote_path"`
	FileID string `json:"file_id"`
}

// Socks is used to send SOCKS data between the SOCKS client and the agent and is an array on the
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/socks#what-do-socks-messages-look-like
type Socks struct {
	ServerId int32  `json:"server_id"`
	Data     string `json:"data"`
	Exit     bool   `json:"exit"`
}

// SocksParams is used as an embedded structure for the Task structure when the Command field is "socks"
type SocksParams struct {
	Action string `json:"action"`
	Port   int    `json:"port"`
}
