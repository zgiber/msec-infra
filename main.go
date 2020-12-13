package main

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"cloud.google.com/go/datastore"
)

// test server
type server struct {
	dc *datastore.Client
}

type request struct {
	ReceivedAt time.Time
	Request    string `datastore:",noindex"`
}

func main() {
	projID := os.Getenv("DATASTORE_PROJECT_ID")
	if projID == "" {
		log.Fatal(`You need to set the environment variable "DATASTORE_PROJECT_ID"`)
	}
	// [START datastore_build_service]
	ctx := context.Background()
	client, err := datastore.NewClient(ctx, projID)
	// [END datastore_build_service]
	if err != nil {
		log.Fatalf("Could not create datastore client: %v", err)
	}

	srv := &server{
		dc: client,
	}

	// catch all
	err = http.ListenAndServe(":8088", http.HandlerFunc(srv.handleAllRequests))
	if err != nil {
		log.Println(err)
	}
}

func (s *server) handleAllRequests(w http.ResponseWriter, r *http.Request) {
	rb, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Println(err)
	}

	storedRequest := &request{
		ReceivedAt: time.Now().UTC(),
		Request:    string(rb),
	}

	key, err := s.dc.Put(r.Context(), datastore.IncompleteKey("request", nil), storedRequest)
	if err != nil {
		log.Println(err)
	}
	log.Printf("stored request with id: %s", key)
}
