package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/dgrijalva/jwt-go"
)

const (
	githubBaseAPI = "https://api.github.com"
)

// test server
type server struct {
	l             sync.RWMutex
	privateKey    []byte
	appID         string
	installations map[int]*installationAuth
	datastore     *datastore.Client
}

type request struct {
	ReceivedAt time.Time
	Request    string `datastore:",noindex"`
}

func main() {
	// projID := os.Getenv("DATASTORE_PROJECT_ID")
	// if projID == "" {
	// 	log.Fatal(`You need to set the environment variable "DATASTORE_PROJECT_ID"`)
	// }

	privateKeyB64 := os.Getenv("GITHUB_APP_PRIVATE_KEY")
	if privateKeyB64 == "" {
		log.Fatal(`You need to set the environment variable "GITHUB_APP_PRIVATE_KEY"`)
	}

	privateKey, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		log.Fatal(err)
	}

	appID := os.Getenv("GITHUB_APP_ID")
	if appID == "" {
		log.Fatal(`You need to set the environment variable "GITHUB_APP_ID"`)
	}

	// [START datastore_build_service]
	// ctx := context.Background()
	// client, err := datastore.NewClient(ctx, projID)
	// [END datastore_build_service]
	// if err != nil {
	// log.Fatalf("Could not create datastore client: %v", err)
	// }

	srv := &server{
		privateKey:    privateKey,
		appID:         appID,
		installations: map[int]*installationAuth{},
		// datastore:     client,
	}

	// catch all
	err = http.ListenAndServe(":8088", http.HandlerFunc(srv.handleAllRequests))
	if err != nil {
		log.Println(err)
	}
}

func (s *server) handleAllRequests(w http.ResponseWriter, r *http.Request) {
	webhook := &webhook{}
	err := json.NewDecoder(r.Body).Decode(webhook)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token, err := s.getInstallationAuthToken(webhook.Installation.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	contents, err := s.getRepositoryContent(token, webhook.Repository.Owner.Name, webhook.Repository.Name)
	// testing stuff
	w.Write(contents)
}

func (s *server) getRepositoryContent(token, owner, repo string) ([]byte, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/contents", githubBaseAPI, owner, repo)
	r, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate as Installation: %w", err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Accept", "application/vnd.github.machine-man-preview+json")
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate as Installation: %w", err)
	}

	// TODO: should we care about redirects?
	if response.StatusCode/100 != 2 {
		err := fmt.Errorf("remote error (%v)", response.StatusCode)
		return nil, fmt.Errorf("failed to authenticate as Installation: %w", err)
	}
	defer response.Body.Close()
	return ioutil.ReadAll(response.Body)
}

func (s *server) getInstallationAuthToken(installationID int) (string, error) {
	now := time.Now().UTC()
	s.l.RLock()
	auth, ok := s.installations[installationID]
	s.l.RUnlock()
	if ok {
		if auth.ExpiresAt.After(now.Add(10 * time.Second)) {
			return auth.Token, nil
		}
	}

	// claims required by Github
	claims := map[string]interface{}{
		"iat": now.Unix(),
		"exp": now.Unix() + 600,
		"iss": s.appID,
	}

	jwt, err := createJWTString(claims, s.privateKey)
	if err != nil {
		return "", err
	}

	// for accessing installation specific data (e.g. contents) we need to auth as the installation
	auth, err = authAsInstallation(jwt, installationID)
	if err != nil {
		return "", err
	}

	s.l.Lock()
	// keep it for a short while (until it expires)
	s.installations[installationID] = auth
	s.l.Unlock()
	return auth.Token, nil
}

func authAsInstallation(jwt string, installationID int) (*installationAuth, error) {
	url := fmt.Sprintf("https://api.github.com/app/installations/%v/access_tokens", installationID)
	r, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate as Installation: %w", err)
	}
	r.Header.Set("Authorization", "Bearer "+jwt)
	r.Header.Set("Accept", "application/vnd.github.machine-man-preview+json")
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate as Installation: %w", err)
	}

	// TODO: should we care about redirects?
	if response.StatusCode/100 != 2 {
		err := fmt.Errorf("remote error (%v)", response.StatusCode)
		return nil, fmt.Errorf("failed to authenticate as Installation: %w", err)
	}
	defer response.Body.Close()
	auth := &installationAuth{}
	err = json.NewDecoder(response.Body).Decode(auth)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate as Installation: %w", err)
	}

	return auth, nil
}

// creates a JWT as a string signed with the private key for the Github app using RS256 alg.
func createJWTString(claims map[string]interface{}, privateKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return "", err
	}

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

type installationAuth struct {
	Token       string    `json:"token"`
	ExpiresAt   time.Time `json:"expires_at"`
	Permissions struct {
		Actions              string `json:"actions"`
		Checks               string `json:"checks"`
		Contents             string `json:"contents"`
		Metadata             string `json:"metadata"`
		RepositoryHooks      string `json:"repository_hooks"`
		SecretScanningAlerts string `json:"secret_scanning_alerts"`
		SecurityEvents       string `json:"security_events"`
		Statuses             string `json:"statuses"`
	} `json:"permissions"`
	RepositorySelection string `json:"repository_selection"`
}

// TODO: remove what's not necessary
type webhook struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	Repository struct {
		ID       int    `json:"id"`
		NodeID   string `json:"node_id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		Private  bool   `json:"private"`
		Owner    struct {
			Name              string `json:"name"`
			Email             string `json:"email"`
			Login             string `json:"login"`
			ID                int    `json:"id"`
			NodeID            string `json:"node_id"`
			AvatarURL         string `json:"avatar_url"`
			GravatarID        string `json:"gravatar_id"`
			URL               string `json:"url"`
			HTMLURL           string `json:"html_url"`
			FollowersURL      string `json:"followers_url"`
			FollowingURL      string `json:"following_url"`
			GistsURL          string `json:"gists_url"`
			StarredURL        string `json:"starred_url"`
			SubscriptionsURL  string `json:"subscriptions_url"`
			OrganizationsURL  string `json:"organizations_url"`
			ReposURL          string `json:"repos_url"`
			EventsURL         string `json:"events_url"`
			ReceivedEventsURL string `json:"received_events_url"`
			Type              string `json:"type"`
			SiteAdmin         bool   `json:"site_admin"`
		} `json:"owner"`
		HTMLURL          string      `json:"html_url"`
		Description      interface{} `json:"description"`
		Fork             bool        `json:"fork"`
		URL              string      `json:"url"`
		ForksURL         string      `json:"forks_url"`
		KeysURL          string      `json:"keys_url"`
		CollaboratorsURL string      `json:"collaborators_url"`
		TeamsURL         string      `json:"teams_url"`
		HooksURL         string      `json:"hooks_url"`
		IssueEventsURL   string      `json:"issue_events_url"`
		EventsURL        string      `json:"events_url"`
		AssigneesURL     string      `json:"assignees_url"`
		BranchesURL      string      `json:"branches_url"`
		TagsURL          string      `json:"tags_url"`
		BlobsURL         string      `json:"blobs_url"`
		GitTagsURL       string      `json:"git_tags_url"`
		GitRefsURL       string      `json:"git_refs_url"`
		TreesURL         string      `json:"trees_url"`
		StatusesURL      string      `json:"statuses_url"`
		LanguagesURL     string      `json:"languages_url"`
		StargazersURL    string      `json:"stargazers_url"`
		ContributorsURL  string      `json:"contributors_url"`
		SubscribersURL   string      `json:"subscribers_url"`
		SubscriptionURL  string      `json:"subscription_url"`
		CommitsURL       string      `json:"commits_url"`
		GitCommitsURL    string      `json:"git_commits_url"`
		CommentsURL      string      `json:"comments_url"`
		IssueCommentURL  string      `json:"issue_comment_url"`
		ContentsURL      string      `json:"contents_url"`
		CompareURL       string      `json:"compare_url"`
		MergesURL        string      `json:"merges_url"`
		ArchiveURL       string      `json:"archive_url"`
		DownloadsURL     string      `json:"downloads_url"`
		IssuesURL        string      `json:"issues_url"`
		PullsURL         string      `json:"pulls_url"`
		MilestonesURL    string      `json:"milestones_url"`
		NotificationsURL string      `json:"notifications_url"`
		LabelsURL        string      `json:"labels_url"`
		ReleasesURL      string      `json:"releases_url"`
		DeploymentsURL   string      `json:"deployments_url"`
		CreatedAt        int         `json:"created_at"`
		UpdatedAt        time.Time   `json:"updated_at"`
		PushedAt         int         `json:"pushed_at"`
		GitURL           string      `json:"git_url"`
		SSHURL           string      `json:"ssh_url"`
		CloneURL         string      `json:"clone_url"`
		SvnURL           string      `json:"svn_url"`
		Homepage         interface{} `json:"homepage"`
		Size             int         `json:"size"`
		StargazersCount  int         `json:"stargazers_count"`
		WatchersCount    int         `json:"watchers_count"`
		Language         string      `json:"language"`
		HasIssues        bool        `json:"has_issues"`
		HasProjects      bool        `json:"has_projects"`
		HasDownloads     bool        `json:"has_downloads"`
		HasWiki          bool        `json:"has_wiki"`
		HasPages         bool        `json:"has_pages"`
		ForksCount       int         `json:"forks_count"`
		MirrorURL        interface{} `json:"mirror_url"`
		Archived         bool        `json:"archived"`
		Disabled         bool        `json:"disabled"`
		OpenIssuesCount  int         `json:"open_issues_count"`
		License          interface{} `json:"license"`
		Forks            int         `json:"forks"`
		OpenIssues       int         `json:"open_issues"`
		Watchers         int         `json:"watchers"`
		DefaultBranch    string      `json:"default_branch"`
		Stargazers       int         `json:"stargazers"`
		MasterBranch     string      `json:"master_branch"`
	} `json:"repository"`
	Pusher struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"pusher"`
	Sender struct {
		Login             string `json:"login"`
		ID                int    `json:"id"`
		NodeID            string `json:"node_id"`
		AvatarURL         string `json:"avatar_url"`
		GravatarID        string `json:"gravatar_id"`
		URL               string `json:"url"`
		HTMLURL           string `json:"html_url"`
		FollowersURL      string `json:"followers_url"`
		FollowingURL      string `json:"following_url"`
		GistsURL          string `json:"gists_url"`
		StarredURL        string `json:"starred_url"`
		SubscriptionsURL  string `json:"subscriptions_url"`
		OrganizationsURL  string `json:"organizations_url"`
		ReposURL          string `json:"repos_url"`
		EventsURL         string `json:"events_url"`
		ReceivedEventsURL string `json:"received_events_url"`
		Type              string `json:"type"`
		SiteAdmin         bool   `json:"site_admin"`
	} `json:"sender"`
	Installation struct {
		ID     int    `json:"id"`
		NodeID string `json:"node_id"`
	} `json:"installation"`
	Created bool        `json:"created"`
	Deleted bool        `json:"deleted"`
	Forced  bool        `json:"forced"`
	BaseRef interface{} `json:"base_ref"`
	Compare string      `json:"compare"`
	Commits []struct {
		ID        string    `json:"id"`
		TreeID    string    `json:"tree_id"`
		Distinct  bool      `json:"distinct"`
		Message   string    `json:"message"`
		Timestamp time.Time `json:"timestamp"`
		URL       string    `json:"url"`
		Author    struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Username string `json:"username"`
		} `json:"author"`
		Committer struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Username string `json:"username"`
		} `json:"committer"`
		Added    []interface{} `json:"added"`
		Removed  []interface{} `json:"removed"`
		Modified []string      `json:"modified"`
	} `json:"commits"`
	HeadCommit struct {
		ID        string    `json:"id"`
		TreeID    string    `json:"tree_id"`
		Distinct  bool      `json:"distinct"`
		Message   string    `json:"message"`
		Timestamp time.Time `json:"timestamp"`
		URL       string    `json:"url"`
		Author    struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Username string `json:"username"`
		} `json:"author"`
		Committer struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Username string `json:"username"`
		} `json:"committer"`
		Added    []interface{} `json:"added"`
		Removed  []interface{} `json:"removed"`
		Modified []string      `json:"modified"`
	} `json:"head_commit"`
}
