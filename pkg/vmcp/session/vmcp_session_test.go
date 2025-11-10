package session

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transportsession "github.com/stacklok/toolhive/pkg/transport/session"
	"github.com/stacklok/toolhive/pkg/vmcp"
)

func TestNewVMCPSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		sessionID string
		wantNilRT bool
		wantType  transportsession.SessionType
	}{
		{
			name:      "creates session with valid ID",
			sessionID: "test-session-123",
			wantNilRT: true,
			wantType:  transportsession.SessionTypeStreamable,
		},
		{
			name:      "creates session with empty ID",
			sessionID: "",
			wantNilRT: true,
			wantType:  transportsession.SessionTypeStreamable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sess := NewVMCPSession(tt.sessionID)

			require.NotNil(t, sess)
			assert.Equal(t, tt.sessionID, sess.ID())
			assert.Equal(t, tt.wantType, sess.Type())

			if tt.wantNilRT {
				assert.Nil(t, sess.GetRoutingTable())
			}

			// Verify embedded StreamableSession is initialized
			assert.NotNil(t, sess.StreamableSession)
		})
	}
}

func TestVMCPSession_GetSetRoutingTable(t *testing.T) {
	t.Parallel()

	sess := NewVMCPSession("test-session")
	require.NotNil(t, sess)

	// Initially nil
	assert.Nil(t, sess.GetRoutingTable())

	// Create a routing table
	rt := &vmcp.RoutingTable{
		Tools: map[string]*vmcp.BackendTarget{
			"tool1": {
				WorkloadID:   "backend1",
				WorkloadName: "Backend 1",
				BaseURL:      "http://localhost:8080",
			},
		},
		Resources: map[string]*vmcp.BackendTarget{
			"resource://test": {
				WorkloadID:   "backend2",
				WorkloadName: "Backend 2",
				BaseURL:      "http://localhost:8081",
			},
		},
		Prompts: map[string]*vmcp.BackendTarget{
			"prompt1": {
				WorkloadID:   "backend3",
				WorkloadName: "Backend 3",
				BaseURL:      "http://localhost:8082",
			},
		},
	}

	// Set routing table
	sess.SetRoutingTable(rt)

	// Verify retrieval
	retrieved := sess.GetRoutingTable()
	require.NotNil(t, retrieved)
	assert.Equal(t, rt, retrieved)
	assert.Len(t, retrieved.Tools, 1)
	assert.Len(t, retrieved.Resources, 1)
	assert.Len(t, retrieved.Prompts, 1)
}

func TestVMCPSession_GetData(t *testing.T) {
	t.Parallel()

	sess := NewVMCPSession("test-session")
	require.NotNil(t, sess)

	// GetData should return nil initially
	assert.Nil(t, sess.GetData())

	// Set routing table
	rt := &vmcp.RoutingTable{
		Tools: map[string]*vmcp.BackendTarget{
			"tool1": {
				WorkloadID: "backend1",
				BaseURL:    "http://localhost:8080",
			},
		},
	}
	sess.SetRoutingTable(rt)

	// GetData should return the routing table
	data := sess.GetData()
	require.NotNil(t, data)

	retrievedRT, ok := data.(*vmcp.RoutingTable)
	require.True(t, ok, "GetData should return *RoutingTable")
	assert.Equal(t, rt, retrievedRT)
}

func TestVMCPSession_SetData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		data          interface{}
		wantNilRT     bool
		wantToolCount int
	}{
		{
			name: "sets routing table directly",
			data: &vmcp.RoutingTable{
				Tools: map[string]*vmcp.BackendTarget{
					"tool1": {WorkloadID: "backend1"},
					"tool2": {WorkloadID: "backend2"},
				},
			},
			wantNilRT:     false,
			wantToolCount: 2,
		},
		{
			name: "deserializes from JSON",
			data: json.RawMessage(`{
				"Tools": {
					"tool1": {
						"WorkloadID": "backend1",
						"WorkloadName": "Backend 1",
						"BaseURL": "http://localhost:8080"
					}
				},
				"Resources": {},
				"Prompts": {}
			}`),
			wantNilRT:     false,
			wantToolCount: 1,
		},
		{
			name:      "handles nil data",
			data:      nil,
			wantNilRT: true,
		},
		{
			name:      "handles invalid JSON",
			data:      json.RawMessage(`{invalid json`),
			wantNilRT: true,
		},
		{
			name:      "handles unexpected type",
			data:      "some string",
			wantNilRT: true,
		},
		{
			name:      "handles map type",
			data:      map[string]int{"foo": 42},
			wantNilRT: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sess := NewVMCPSession("test-session")
			require.NotNil(t, sess)

			sess.SetData(tt.data)

			rt := sess.GetRoutingTable()
			if tt.wantNilRT {
				assert.Nil(t, rt)
			} else {
				require.NotNil(t, rt)
				assert.Len(t, rt.Tools, tt.wantToolCount)
			}
		})
	}
}

func TestVMCPSession_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	sess := NewVMCPSession("test-session")
	require.NotNil(t, sess)

	// Create routing tables for concurrent writes
	rt1 := &vmcp.RoutingTable{
		Tools: map[string]*vmcp.BackendTarget{
			"tool1": {WorkloadID: "backend1"},
		},
	}
	rt2 := &vmcp.RoutingTable{
		Tools: map[string]*vmcp.BackendTarget{
			"tool2": {WorkloadID: "backend2"},
		},
	}

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent writes
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			sess.SetRoutingTable(rt1)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			sess.SetRoutingTable(rt2)
		}
	}()

	// Concurrent reads
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = sess.GetRoutingTable()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = sess.GetData()
		}
	}()

	// Wait for all goroutines
	wg.Wait()

	// Verify session is still valid
	rt := sess.GetRoutingTable()
	require.NotNil(t, rt)
	assert.NotEmpty(t, rt.Tools)
}

func TestVMCPSession_Type(t *testing.T) {
	t.Parallel()

	sess := NewVMCPSession("test-session")
	require.NotNil(t, sess)

	assert.Equal(t, transportsession.SessionTypeStreamable, sess.Type())
}

func TestVMCPSessionFactory(t *testing.T) {
	t.Parallel()

	factory := VMCPSessionFactory()
	require.NotNil(t, factory)

	// Create session using factory
	sess := factory("test-session-123")
	require.NotNil(t, sess)

	// Verify it's a VMCPSession
	vmcpSess, ok := sess.(*VMCPSession)
	require.True(t, ok, "Factory should return *VMCPSession")
	assert.Equal(t, "test-session-123", vmcpSess.ID())
	assert.Equal(t, transportsession.SessionTypeStreamable, vmcpSess.Type())
	assert.Nil(t, vmcpSess.GetRoutingTable())
}

func TestVMCPSession_SessionInterface(t *testing.T) {
	t.Parallel()

	// Verify VMCPSession implements transportsession.Session interface
	var _ transportsession.Session = (*VMCPSession)(nil)

	sess := NewVMCPSession("test-session")
	require.NotNil(t, sess)

	// Test Session interface methods
	assert.NotEmpty(t, sess.ID())
	assert.Equal(t, transportsession.SessionTypeStreamable, sess.Type())
	assert.NotZero(t, sess.CreatedAt())
	assert.NotZero(t, sess.UpdatedAt())

	// Test Touch updates timestamp
	firstUpdate := sess.UpdatedAt()
	sess.Touch()
	secondUpdate := sess.UpdatedAt()
	assert.True(t, secondUpdate.After(firstUpdate) || secondUpdate.Equal(firstUpdate))

	// Test metadata methods
	sess.SetMetadata("key1", "value1")
	val, ok := sess.GetMetadataValue("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)

	metadata := sess.GetMetadata()
	assert.Contains(t, metadata, "key1")
}

func TestVMCPSession_SerializationRoundTrip(t *testing.T) {
	t.Parallel()

	// Create session with routing table
	sess := NewVMCPSession("test-session")
	rt := &vmcp.RoutingTable{
		Tools: map[string]*vmcp.BackendTarget{
			"tool1": {
				WorkloadID:             "backend1",
				WorkloadName:           "Backend 1",
				BaseURL:                "http://localhost:8080",
				TransportType:          "http",
				OriginalCapabilityName: "original_tool1",
				AuthStrategy:           "pass_through",
			},
		},
		Resources: map[string]*vmcp.BackendTarget{
			"resource://test": {
				WorkloadID:   "backend2",
				WorkloadName: "Backend 2",
				BaseURL:      "http://localhost:8081",
			},
		},
	}
	sess.SetRoutingTable(rt)

	// Serialize via GetData
	data := sess.GetData()
	require.NotNil(t, data)

	// Marshal to JSON (simulating storage backend)
	jsonData, err := json.Marshal(data)
	require.NoError(t, err)

	// Create new session and deserialize
	sess2 := NewVMCPSession("test-session-2")
	sess2.SetData(json.RawMessage(jsonData))

	// Verify routing table is correctly deserialized
	rt2 := sess2.GetRoutingTable()
	require.NotNil(t, rt2)
	assert.Len(t, rt2.Tools, 1)
	assert.Len(t, rt2.Resources, 1)

	tool1, ok := rt2.Tools["tool1"]
	require.True(t, ok)
	assert.Equal(t, "backend1", tool1.WorkloadID)
	assert.Equal(t, "Backend 1", tool1.WorkloadName)
	assert.Equal(t, "http://localhost:8080", tool1.BaseURL)
	assert.Equal(t, "original_tool1", tool1.OriginalCapabilityName)
}

func TestVMCPSession_NilRoutingTable(t *testing.T) {
	t.Parallel()

	sess := NewVMCPSession("test-session")

	// Set nil routing table
	sess.SetRoutingTable(nil)
	assert.Nil(t, sess.GetRoutingTable())

	// GetData should return nil
	assert.Nil(t, sess.GetData())

	// SetData with nil
	sess.SetData(nil)
	assert.Nil(t, sess.GetRoutingTable())
}
