package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// --- Data Models ---

type AuthRequest struct {
	LoginName string `json:"loginName"`
	Password  string `json:"password"`
}

type AuthResponse struct {
	SslId   string `json:"sslId"`
	Message string `json:"message"`
}

type EnrollRequest struct {
	Csr         string `json:"csr"`
	Term        int    `json:"term"`
	ProductCode int    `json:"productCode"`
}

type EnrollResponse struct {
	SslId   int    `json:"sslId"`
	Message string `json:"message"`
}

type RevokeRequest struct {
	SslId  string `json:"sslId"`
	Reason string `json:"reason"`
}

type RevokeResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type Order struct {
	ID          int
	CSR         string
	Status      string // "pending", "issued", "revoked"
	Certificate string // PEM content
	CreatedAt   time.Time
}

// --- In-Memory Store ---

var (
	orders  = make(map[int]*Order)
	mu      sync.RWMutex
	nextID  = 12345
)

// --- Handlers ---

func handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Mock Validation: Allow everything for now, or check for specific values
	// In a real scenario, check DB.
	log.Printf("[Auth] User: %s", req.LoginName)

	resp := AuthResponse{
		SslId:   generateRandomSessionID(),
		Message: "Authentication successful",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check Auth Headers (Mock)
	// token := r.Header.Get("token") ...

	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	mu.Lock()
	orderID := nextID
	nextID++
	
	// Create Mock Certificate immediately for simplicity, or wait for status check
	cert := generateFakeCert()

	orders[orderID] = &Order{
		ID:          orderID,
		CSR:         req.Csr,
		Status:      "pending", // Start as pending, auto-approve later or immediately?
		Certificate: cert,
		CreatedAt:   time.Now(),
	}
	mu.Unlock()

	// Simulate background issuance
	go func(id int) {
		time.Sleep(5 * time.Second) // Wait 5 seconds to simulate validation
		mu.Lock()
		if o, ok := orders[id]; ok {
			o.Status = "issued"
			log.Printf("[Enroll] Order %d status changed to issued", id)
		}
		mu.Unlock()
	}(orderID)

	log.Printf("[Enroll] New Order ID: %d", orderID)

	resp := EnrollResponse{
		SslId:   orderID,
		Message: "Order created successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pathParts := strings.Split(r.URL.Path, "/")
	// /api/ssl/v1/status/{id} -> ["", "api", "ssl", "v1", "status", "{id}"]
	if len(pathParts) < 6 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	idStr := pathParts[5] // The ID
	var orderID int
	_, err := fmt.Sscanf(idStr, "%d", &orderID)
	if err != nil {
		http.Error(w, "Invalid Order ID format", http.StatusBadRequest)
		return
	}

	mu.RLock()
	order, ok := orders[orderID]
	mu.RUnlock()

	if !ok {
		http.Error(w, "Order not found", http.StatusNotFound)
		return
	}

	// Mocking status response structure - assuming simple structure or Just string
	// Real Sectigo API might return JSON with status field.
	w.Header().Set("Content-Type", "application/json")
	// Returning a map for flexibility
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sslId": orderID,
		"status": order.Status,
	})
}

func handleCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 6 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	idStr := pathParts[5] // The ID
	var orderID int
	_, err := fmt.Sscanf(idStr, "%d", &orderID)
	if err != nil {
		http.Error(w, "Invalid Order ID format", http.StatusBadRequest)
		return
	}

	mu.RLock()
	order, ok := orders[orderID]
	mu.RUnlock()

	if !ok {
		http.Error(w, "Order not found", http.StatusNotFound)
		return
	}

	if order.Status != "issued" {
		http.Error(w, "Certificate not ready (status: "+order.Status+")", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%d.crt\"", orderID))
	w.Write([]byte(order.Certificate))
}

func handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var orderID int
	_, err := fmt.Sscanf(req.SslId, "%d", &orderID)
	
	// Handle string fake ID if scan fails, maybe just log it
	if err != nil {
		// Try to see if it's our int ID
		// In real usage, maybe check both
	}

	mu.Lock()
	// Simple lookup
	var found bool
	for _, o := range orders {
		// Mock logic: assuming req.SslId matches our int ID string representation
		if fmt.Sprintf("%d", o.ID) == req.SslId {
			o.Status = "revoked"
			found = true
			break
		}
	}
	mu.Unlock()

	resp := RevokeResponse{
		Status:  "success",
		Message: "Certificate revoked",
	}
	if !found {
		resp.Status = "failure"
		resp.Message = "Order not found"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// --- Helpers ---

func generateRandomSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateFakeCert() string {
	return `-----BEGIN CERTIFICATE-----
MIIQD...... (Mock Certificate Data) ......
......
......
-----END CERTIFICATE-----`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ssl/v1/user/auth", handleAuth)
	mux.HandleFunc("/api/ssl/v1/enroll", handleEnroll)
	mux.HandleFunc("/api/ssl/v1/status/", handleStatus)   // Trailing slash for path params
	mux.HandleFunc("/api/ssl/v1/collect/", handleCollect) // Trailing slash for path params
	mux.HandleFunc("/api/ssl/v1/revoke", handleRevoke)

	log.Println("Mock Setigo API Server listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
