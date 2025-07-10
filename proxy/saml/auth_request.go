package saml

// AuthRequest implements the models.AuthRequestInt interface.
type AuthRequest struct {
	ID                       string
	ApplicationID            string
	RelayState               string
	AccessConsumerServiceURL string
	BindingType              string
	AuthRequestID            string
	Issuer                   string
	Destination              string
	UserID                   string
	IsDone                   bool
}

func (a *AuthRequest) GetID() string {
	return a.ID
}

func (a *AuthRequest) GetApplicationID() string {
	return a.ApplicationID
}

func (a *AuthRequest) GetRelayState() string {
	return a.RelayState
}

func (a *AuthRequest) GetAccessConsumerServiceURL() string {
	return a.AccessConsumerServiceURL
}

func (a *AuthRequest) GetBindingType() string {
	return a.BindingType
}

func (a *AuthRequest) GetAuthRequestID() string {
	return a.AuthRequestID
}

func (a *AuthRequest) GetIssuer() string {
	return a.Issuer
}

func (a *AuthRequest) GetDestination() string {
	return a.Destination
}

func (a *AuthRequest) GetUserID() string {
	return a.UserID
}

func (a *AuthRequest) Done() bool {
	return a.IsDone
}
