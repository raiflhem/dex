// Package discord provides authentication strategies using Discord.
package discord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/dexidp/dex/connector"
)

// Config holds configuration options for discord logins.
type Config struct {
	BaseURL       string `json:"baseURL"`
	ClientID      string `json:"clientID"`
	ClientSecret  string `json:"clientSecret"`
	RedirectURI   string `json:"redirectURI"`
	Orgs          []Org  `json:"orgs"`
	LoadAllGroups bool   `json:"loadAllGroups"`
	UseLoginAsID  bool   `json:"useLoginAsID"`
}

// Org holds org-team filters, in which teams are optional.
type Org struct {
	// Organization name in discord (not slug, full name). Only users in this gitea
	// organization can authenticate.
	Name string `json:"name"`

	// Names of teams in a discord organization. A user will be able to
	// authenticate if they are members of at least one of these teams. Users
	// in the organization can authenticate if this field is omitted from the
	// config file.
	Teams []string `json:"teams,omitempty"`
}

type discordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

// Open returns a strategy for logging in through discord
func (c *Config) Open(id string, logger *slog.Logger) (connector.Connector, error) {
	if c.BaseURL == "" {
		c.BaseURL = "https://discord.com"
	}
	return &discordConnector{
		baseURL:       c.BaseURL,
		redirectURI:   c.RedirectURI,
		orgs:          c.Orgs,
		clientID:      c.ClientID,
		clientSecret:  c.ClientSecret,
		logger:        logger.With(slog.Group("connector", "type", "discord", "id", id)),
		loadAllGroups: c.LoadAllGroups,
		useLoginAsID:  c.UseLoginAsID,
	}, nil
}

type connectorData struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	Expiry       time.Time `json:"expiry"`
}

var (
	_ connector.CallbackConnector = (*discordConnector)(nil)
	_ connector.RefreshConnector  = (*discordConnector)(nil)
)

type discordConnector struct {
	baseURL      string
	redirectURI  string
	orgs         []Org
	clientID     string
	clientSecret string
	logger       *slog.Logger
	httpClient   *http.Client
	// if set to true and no orgs are configured then connector loads all user claims (all orgs and team)
	loadAllGroups bool
	// if set to true will use the user's handle rather than their numeric id as the ID
	useLoginAsID bool
}

func (c *discordConnector) oauth2Config(_ connector.Scopes) *oauth2.Config {
	discordEndpoint := oauth2.Endpoint{AuthURL: c.baseURL + "/api/oauth2/authorize", TokenURL: c.baseURL + "/api/oauth2/token"}
	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint:     discordEndpoint,
		Scopes:       []string{"email", "identify", "guilds", "openid"},
		RedirectURL:  c.redirectURI,
	}
}

func (c *discordConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", c.redirectURI, callbackURL)
	}
	return c.oauth2Config(scopes).AuthCodeURL(state), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

func (c *discordConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}

	oauth2Config := c.oauth2Config(s)

	ctx := r.Context()
	if c.httpClient != nil {
		ctx = context.WithValue(r.Context(), oauth2.HTTPClient, c.httpClient)
	}

	token, err := oauth2Config.Exchange(ctx, q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("discord: failed to get token: %v", err)
	}

	client := oauth2Config.Client(ctx, token)

	user, err := c.user(ctx, client)
	if err != nil {
		return identity, fmt.Errorf("discord: get user: %v", err)
	}

	username := user.Username
	if username == "" {
		username = user.Email
	}

	identity = connector.Identity{
		UserID:            user.ID,
		Username:          username,
		PreferredUsername: user.Username,
		Email:             user.Email,
		EmailVerified:     user.Verified,
	}
	if c.useLoginAsID {
		identity.UserID = user.Username
	}

	// Only set identity.Groups if 'orgs', 'org', or 'groups' scope are specified.
	if c.groupsRequired() {
		groups, err := c.getGroups(ctx, client)
		if err != nil {
			return identity, err
		}
		identity.Groups = groups
	}

	if s.OfflineAccess {
		data := connectorData{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			Expiry:       token.Expiry,
		}
		connData, err := json.Marshal(data)
		if err != nil {
			return identity, fmt.Errorf("discord: marshal connector data: %v", err)
		}
		identity.ConnectorData = connData
	}

	return identity, nil
}

// Refreshing tokens
// https://github.com/golang/oauth2/issues/84#issuecomment-332860871
type tokenNotifyFunc func(*oauth2.Token) error

// notifyRefreshTokenSource is essentially `oauth2.ReuseTokenSource` with `TokenNotifyFunc` added.
type notifyRefreshTokenSource struct {
	new oauth2.TokenSource
	mu  sync.Mutex // guards t
	t   *oauth2.Token
	f   tokenNotifyFunc // called when token refreshed so new refresh token can be persisted
}

// Token returns the current token if it's still valid, else will
// refresh the current token (using r.Context for HTTP client
// information) and return the new one.
func (s *notifyRefreshTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.t.Valid() {
		return s.t, nil
	}
	t, err := s.new.Token()
	if err != nil {
		return nil, err
	}
	s.t = t
	return t, s.f(t)
}

func (c *discordConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	if len(ident.ConnectorData) == 0 {
		return ident, errors.New("discord: no upstream access token found")
	}

	var data connectorData
	if err := json.Unmarshal(ident.ConnectorData, &data); err != nil {
		return ident, fmt.Errorf("discord: unmarshal access token: %v", err)
	}

	tok := &oauth2.Token{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		Expiry:       data.Expiry,
	}

	client := oauth2.NewClient(ctx, &notifyRefreshTokenSource{
		new: c.oauth2Config(s).TokenSource(ctx, tok),
		t:   tok,
		f: func(tok *oauth2.Token) error {
			data := connectorData{
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken,
				Expiry:       tok.Expiry,
			}
			connData, err := json.Marshal(data)
			if err != nil {
				return fmt.Errorf("discord: marshal connector data: %v", err)
			}
			ident.ConnectorData = connData
			return nil
		},
	})
	user, err := c.user(ctx, client)
	if err != nil {
		return ident, fmt.Errorf("discord: get user: %v", err)
	}

	username := user.Username
	if username == "" {
		username = user.Email
	}
	ident.Username = username
	ident.PreferredUsername = user.Username
	ident.Email = user.Email

	// Only set identity.Groups if 'orgs', 'org', or 'groups' scope are specified.
	if c.groupsRequired() {
		groups, err := c.getGroups(ctx, client)
		if err != nil {
			return ident, err
		}
		ident.Groups = groups
	}

	return ident, nil
}

// getGroups retrieves discord orgs and teams a user is in, if any.
func (c *discordConnector) getGroups(ctx context.Context, client *http.Client) ([]string, error) {
	if len(c.orgs) > 0 {
		return c.groupsForOrgs(ctx, client)
	} else if c.loadAllGroups {
		return c.userGroups(ctx, client)
	}
	return nil, nil
}

// formatTeamName returns unique team name.
// Orgs might have the same team names. To make team name unique it should be prefixed with the org name.
func formatTeamName(org string, team string) string {
	return fmt.Sprintf("%s:%s", org, team)
}

// groupsForOrgs returns list of groups that user belongs to in approved list
func (c *discordConnector) groupsForOrgs(ctx context.Context, client *http.Client) ([]string, error) {
	groups, err := c.userGroups(ctx, client)
	if err != nil {
		return groups, err
	}

	keys := make(map[string]bool)
	for _, o := range c.orgs {
		keys[o.Name] = true
		if o.Teams != nil {
			for _, t := range o.Teams {
				keys[formatTeamName(o.Name, t)] = true
			}
		}
	}
	atLeastOne := false
	filteredGroups := make([]string, 0)
	for _, g := range groups {
		if _, value := keys[g]; value {
			filteredGroups = append(filteredGroups, g)
			atLeastOne = true
		}
	}

	if !atLeastOne {
		return []string{}, fmt.Errorf("discord: User does not belong to any of the approved groups")
	}
	return filteredGroups, nil
}

type organization struct {
	ID   int64  `json:"id"`
	Name string `json:"username"`
}

type team struct {
	ID           int64         `json:"id"`
	Name         string        `json:"name"`
	Organization *organization `json:"organization"`
}

func (c *discordConnector) userGroups(ctx context.Context, client *http.Client) ([]string, error) {
	apiURL := c.baseURL + "/api/v1/user/teams"
	groups := make([]string, 0)
	page := 1
	limit := 20
	for {
		var teams []team
		req, err := http.NewRequest("GET", fmt.Sprintf("%s?page=%d&limit=%d", apiURL, page, limit), nil)
		if err != nil {
			return groups, fmt.Errorf("discord: new req: %v", err)
		}

		req = req.WithContext(ctx)
		resp, err := client.Do(req)
		if err != nil {
			return groups, fmt.Errorf("discord: get URL %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return groups, fmt.Errorf("discord: read body: %v", err)
			}
			return groups, fmt.Errorf("%s: %s", resp.Status, body)
		}

		if err := json.NewDecoder(resp.Body).Decode(&teams); err != nil {
			return groups, fmt.Errorf("failed to decode response: %v", err)
		}

		if len(teams) == 0 {
			break
		}

		for _, t := range teams {
			groups = append(groups, t.Organization.Name)
			groups = append(groups, formatTeamName(t.Organization.Name, t.Name))
		}

		page++
	}

	// remove duplicate slice variables
	keys := make(map[string]struct{})
	list := []string{}
	for _, group := range groups {
		if _, exists := keys[group]; !exists {
			keys[group] = struct{}{}
			list = append(list, group)
		}
	}
	groups = list
	return groups, nil
}

// user queries the discord API for profile information using the provided client. The HTTP
// client is expected to be constructed by the golang.org/x/oauth2 package, which inserts
// a bearer token as part of the request.
func (c *discordConnector) user(ctx context.Context, client *http.Client) (discordUser, error) {
	var u discordUser
	req, err := http.NewRequest("GET", c.baseURL+"/api/users/@me", nil)
	if err != nil {
		return u, fmt.Errorf("discord: new req: %v", err)
	}
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return u, fmt.Errorf("discord: get URL %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return u, fmt.Errorf("discord: read body: %v", err)
		}
		return u, fmt.Errorf("%s: %s", resp.Status, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return u, fmt.Errorf("failed to decode response: %v", err)
	}
	return u, nil
}

// groupsRequired returns whether dex needs to request groups from discord.
func (c *discordConnector) groupsRequired() bool {
	return len(c.orgs) > 0 || c.loadAllGroups
}
