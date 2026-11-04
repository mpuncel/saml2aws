package browser

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/playwright-community/playwright-go"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

var logger = logrus.WithField("provider", "browser")

const DEFAULT_TIMEOUT float64 = 300000

// Client client for browser based Identity Provider
type Client struct {
	BrowserType           string
	BrowserExecutablePath string
	Headless              bool
	// Setup alternative directory to download playwright browsers to
	BrowserDriverDir string
	Timeout          int
	BrowserAutoFill  bool
	// Browser profile directory, reused between logins
	BrowserProfileDir string
	// Seconds to wait for browser policy after creating a new profile
	BrowserPolicyWarmup int
}

// New create new browser based client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	return &Client{
		Headless:              idpAccount.Headless,
		BrowserDriverDir:      idpAccount.BrowserDriverDir,
		BrowserType:           strings.ToLower(idpAccount.BrowserType),
		BrowserExecutablePath: idpAccount.BrowserExecutablePath,
		Timeout:               idpAccount.Timeout,
		BrowserAutoFill:       idpAccount.BrowserAutoFill,
		BrowserProfileDir:     idpAccount.BrowserProfileDir,
		BrowserPolicyWarmup:   idpAccount.BrowserPolicyWarmup,
	}, nil
}

// contains checks if a string is present in a slice
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
func (cl *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	runOptions := playwright.RunOptions{}
	if cl.BrowserDriverDir != "" {
		runOptions.DriverDirectory = cl.BrowserDriverDir
	}

	// Optionally download browser drivers if specified
	if loginDetails.DownloadBrowser {
		err := playwright.Install(&runOptions)
		if err != nil {
			return "", err
		}
	}

	pw, err := playwright.Run(&runOptions)
	if err != nil {
		return "", err
	}

	// TODO: provide some overrides for this window
	launchOptions := playwright.BrowserTypeLaunchPersistentContextOptions{
		Headless: playwright.Bool(cl.Headless),
	}

	validBrowserTypes := []string{"chromium", "firefox", "webkit", "chrome", "chrome-beta", "chrome-dev", "chrome-canary", "msedge", "msedge-beta", "msedge-dev", "msedge-canary"}
	if len(cl.BrowserType) > 0 && !contains(validBrowserTypes, cl.BrowserType) {
		return "", fmt.Errorf("invalid browser-type: '%s', only %s are allowed", cl.BrowserType, validBrowserTypes)
	}

	if cl.BrowserType != "" {
		logger.Info(fmt.Sprintf("Setting browser type: %s", cl.BrowserType))
		launchOptions.Channel = playwright.String(cl.BrowserType)
	}

	// Default browser is Chromium as it is widely supported for Identity providers,
	// It can also be set to the other playwright browsers: Firefox and WebKit
	browserType := pw.Chromium
	if cl.BrowserType == "firefox" {
		browserType = pw.Firefox
	} else if cl.BrowserType == "webkit" {
		browserType = pw.WebKit
	}

	// You can set the path to a browser executable to run instead of the playwright-go bundled one. If `executablePath`
	// is a relative path, then it is resolved relative to the current working directory.
	// Note that Playwright only works with the bundled Chromium, Firefox or WebKit, use at your own risk. see:
	if len(cl.BrowserExecutablePath) > 0 {
		logger.Info(fmt.Sprintf("Setting browser executable path: %s", cl.BrowserExecutablePath))
		launchOptions.ExecutablePath = &cl.BrowserExecutablePath
	}

	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	storageStatePath := fmt.Sprintf("%s/.aws/saml2aws/storageState.json", userHomeDir)

	profileDir := filepath.Join(userHomeDir, ".aws", "saml2aws", "browser-profile")
	if cl.BrowserProfileDir != "" {
		if profileDir, err = homedir.Expand(cl.BrowserProfileDir); err != nil {
			return "", err
		}
	}
	warmup := time.Duration(cl.BrowserPolicyWarmup) * time.Second

	context, cleanup, err := launchPersistentContext(browserType, launchOptions, profileDir, warmup)
	if err != nil {
		return "", err
	}

	// Persistent contexts can't take a storageState option, so restore the
	// saved cookies explicitly.
	if cookies, err := loadStorageStateCookies(storageStatePath); err != nil {
		logger.Info("Error loading storage state", err)
	} else if len(cookies) > 0 {
		if err := context.AddCookies(cookies); err != nil {
			logger.Info("Error restoring storage state cookies", err)
		}
	}

	var page playwright.Page
	if pages := context.Pages(); len(pages) > 0 {
		page = pages[0]
	} else if page, err = context.NewPage(); err != nil {
		cleanup()
		return "", err
	}

	defer func() {
		logger.Info("saving storage state")
		_, err := context.StorageState(storageStatePath)
		if err != nil {
			logger.Info("Error saving storage state", err)
		}
		logger.Info("clean up browser")
		cleanup()
		if err := pw.Stop(); err != nil {
			logger.Info("Error when stopping pm", err)
		}
	}()

	return getSAMLResponse(page, loginDetails, cl)
}

// launchPersistentContext launches the browser into the default context of
// profileDir rather than via browser.NewContext(): Playwright creates new
// contexts off-the-record, and Chrome disables Enterprise Connectors (Device
// Trust) there, so IdPs that check device posture through Chrome Device
// Trust see no device signals. If profileDir is held by another login, a
// throwaway profile is used instead.
//
// A newly created profile waits for warmup before returning. Managed Chrome
// fetches its cloud policy (which turns on Device Trust) a few seconds after
// starting with an empty profile, and an IdP redirect that arrives first gets
// no device signals. Reused profiles start with the cached policy.
//
// The returned cleanup closes the context and removes any throwaway profile.
func launchPersistentContext(browserType playwright.BrowserType, options playwright.BrowserTypeLaunchPersistentContextOptions, profileDir string, warmup time.Duration) (playwright.BrowserContext, func(), error) {
	_, statErr := os.Stat(profileDir)
	fresh := errors.Is(statErr, os.ErrNotExist)
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		return nil, nil, err
	}
	context, err := browserType.LaunchPersistentContext(profileDir, options)
	removeDir := ""
	if err != nil {
		logger.Info(fmt.Sprintf("browser profile %s unavailable (%v); using a throwaway profile", profileDir, err))
		if removeDir, err = os.MkdirTemp("", "saml2aws-browser-"); err != nil {
			return nil, nil, err
		}
		if context, err = browserType.LaunchPersistentContext(removeDir, options); err != nil {
			_ = os.RemoveAll(removeDir)
			return nil, nil, err
		}
		fresh = true
	}
	if fresh && warmup > 0 {
		logger.Info(fmt.Sprintf("new browser profile; waiting %s for browser policy", warmup))
		time.Sleep(warmup)
	}
	cleanup := func() {
		if err := context.Close(); err != nil {
			logger.Info("Error when closing context", err)
		}
		if removeDir != "" {
			if err := os.RemoveAll(removeDir); err != nil {
				logger.Info("Error removing browser profile", err)
			}
		}
	}
	return context, cleanup, nil
}

// loadStorageStateCookies reads the cookies from a Playwright storageState
// file. A missing file is not an error.
func loadStorageStateCookies(path string) ([]playwright.OptionalCookie, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state struct {
		Cookies []playwright.OptionalCookie `json:"cookies"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return state.Cookies, nil
}

var getSAMLResponse = func(page playwright.Page, loginDetails *creds.LoginDetails, client *Client) (string, error) {
	var data string
	var dataErr error

	logger.WithField("URL", loginDetails.URL).Info("opening browser")

	signin_re, err := signinRegex()
	if err != nil {
		return "", err
	}

	page.OnRequest(func(request playwright.Request) {
		if signin_re.Match([]byte(request.URL())) {
			data, dataErr = request.PostData()
		}
	})
	if _, err := page.Goto(loginDetails.URL); err != nil {
		return "", err
	}

	if client.BrowserAutoFill {
		err := autoFill(page, loginDetails)
		if err != nil {
			logger.Error("error when auto filling", err)
		}
	}

	logger.Info("waiting ...")
	if data == "" {
		r, err := page.ExpectRequest(signin_re, nil, client.expectRequestTimeout())
		if err != nil {
			logger.Error(err)
		}
		data, dataErr = r.PostData()
	}
	if dataErr != nil {
		return "", err
	}

	values, err := url.ParseQuery(data)
	if err != nil {
		return "", err
	}

	return values.Get("SAMLResponse"), nil
}

var autoFill = func(page playwright.Page, loginDetails *creds.LoginDetails) error {
	passwordField := page.Locator("input[type='password']")
	err := passwordField.WaitFor(playwright.LocatorWaitForOptions{
		State: playwright.WaitForSelectorStateVisible,
	})

	if err != nil {
		return err
	}

	err = passwordField.Fill(loginDetails.Password)
	if err != nil {
		return err
	}

	keyboard := page.Keyboard()

	// move to username field which is above password field
	err = keyboard.Press("Shift+Tab")
	if err != nil {
		return err
	}

	err = keyboard.InsertText(loginDetails.Username)
	if err != nil {
		return err
	}

	// Find the submit button or input of the form that the password field is in
	submitLocator := page.Locator("form", playwright.PageLocatorOptions{
		Has: passwordField,
	}).Locator("[type='submit']")
	count, err := submitLocator.Count()
	if err != nil {
		return err
	}

	// when submit locator exists, Click it
	if count > 0 {
		return submitLocator.Click()
	} else { // Use javascript to submit the form when no submit input or button is found
		_, err := page.Evaluate(`document.querySelector('input[type="password"]').form.submit()`, nil)
		return err
	}
}

func signinRegex() (*regexp.Regexp, error) {
	// https://docs.aws.amazon.com/general/latest/gr/signin-service.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Ningxia.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Beijing.html
	return regexp.Compile(`https:\/\/((.*\.)?signin\.(aws\.amazon\.com|amazonaws-us-gov\.com|amazonaws\.cn))\/saml`)
}

func (cl *Client) Validate(loginDetails *creds.LoginDetails) error {

	if loginDetails.URL == "" {
		return errors.New("empty URL")
	}

	return nil
}

func (cl *Client) expectRequestTimeout() playwright.PageExpectRequestOptions {
	timeout := float64(cl.Timeout)
	if timeout < 30000 {
		timeout = DEFAULT_TIMEOUT
	}
	return playwright.PageExpectRequestOptions{Timeout: &timeout}
}
