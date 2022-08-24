package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/hillu/go-yara/v4"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
)

//go:embed rules/*
var rules embed.FS

var (
	signingSecret string
	scanner       yara.Scanner
	api           *slack.Client
)

const (
	slackSigningSecretEnvVar = "SLACK_SIGNING_SECRET"
	slackApiTokenEnvVar      = "SLACK_API_TOKEN"
	warningPre               = "Hello! We have detected there might be some secret disclosure in the message you just sent :|"
	warningPost              = "Please verify if this is the case, and if so, edit the message to remove these and rotate the secrets if possible."
)

var ssmClient *ssm.Client

// called before main
func init() {

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("failed to initiate aws config: %s", err.Error())
	}

	ssmClient = ssm.NewFromConfig(cfg)

	signingSecret = GetParam(slackSigningSecretEnvVar, true)
	apiToken := GetParam(slackApiTokenEnvVar, true)

	if signingSecret == "" || apiToken == "" {
		log.Fatal("Required environment variable(s) missing")
	}

	api = slack.New(apiToken)
	buildRules()
}

func GetParam(name string, withDecryption bool) string {
	input := &ssm.GetParameterInput{
		Name:           &name,
		WithDecryption: withDecryption,
	}

	results, err := ssmClient.GetParameter(context.TODO(), input)
	if err != nil {
		log.Fatalf("couldn't get param with key '%s': %s", name, err.Error())
	}

	if results.Parameter.Value == nil {
		log.Fatalf("failed to find parameter %s", name)
	}

	return *results.Parameter.Value
}

func buildRules() {
	ruleFiles, err := rules.ReadDir("rules")
	if err != nil {
		log.Fatal(err)
	}

	ruleText := ""
	for _, v := range ruleFiles {
		data, err := rules.ReadFile("rules/" + v.Name())
		if err != nil {
			log.Fatal(v.Name(), err)
		}
		ruleText = ruleText + string(data)
	}

	externals := map[string]interface{}{"filename": ""}
	rulesCompiled, err := yara.Compile(ruleText, externals)
	if err != nil {
		log.Fatal("compiling", err)
	}

	scannerCandidate, err := yara.NewScanner(rulesCompiled)
	if err != nil {
		log.Fatal(err)
	}

	scanner = *scannerCandidate
}

func nameFrom(metas []yara.Meta) string {
	for _, v := range metas {
		if v.Identifier == "name" {
			return v.Value.(string)
		}
	}

	return "Unknown"
}

func combine(snippets []yara.MatchString) string {
	r := ""
	for i, v := range snippets {
		r += "`" + string(v.Data) + "`"
		if i < len(snippets)-1 {
			r += ", "
		}
	}
	return r
}

// Handler will check the request comes from the specific slack instance it has a signing secret for, then
// if this passes it will scan message text with the yara rules. Any matches will be combined into a message that
// is sent to the posting user as a ephemeral message using the slack api, so they can choose to take action.
func Handler(w http.ResponseWriter, r *http.Request) {
	log.Println("handler triggered")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sv, err := slack.NewSecretsVerifier(r.Header, signingSecret)
	if err != nil {
		log.Println("missing or invalid slack headers: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Function was not invoked by Slack"))
		return
	}
	if _, err := sv.Write(body); err != nil {
		log.Println("validating the slack headers failed with err: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := sv.Ensure(); err != nil {
		log.Println("invalid signing headers")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid signing headers"))
		return
	}

	log.Println("slack signature verified")

	eventsAPIEvent, err := slackevents.ParseEvent(json.RawMessage(body), slackevents.OptionNoVerifyToken())
	if err != nil {
		log.Println("failed to parse event: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if eventsAPIEvent.Type == slackevents.URLVerification {
		log.Println("type is url verification message")

		var r *slackevents.ChallengeResponse
		err := json.Unmarshal([]byte(body), &r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "text")
		w.Write([]byte(r.Challenge))
	} else if eventsAPIEvent.Type == slackevents.CallbackEvent {
		log.Println("type is call back event")

		innerEvent := eventsAPIEvent.InnerEvent
		switch ev := innerEvent.Data.(type) {
		case *slackevents.MessageEvent:

			var m yara.MatchRules
			err := scanner.SetCallback(&m).ScanMem([]byte(ev.Text))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if len(m) == 0 {
				log.Println("message seems safe")
			} else {

				message := warningPre + "\n\n"
				for _, v := range m {
					message += fmt.Sprintf(" - *%s*: %s\n", nameFrom(v.Metas), combine(v.Strings))
				}
				message += "\n" + warningPost

				respTimestamp, err := api.PostEphemeral(ev.Channel, ev.User, slack.MsgOptionText(message, false))
				if err != nil {
					log.Println("failed to call slack api with err: " + err.Error())
					w.WriteHeader(http.StatusInternalServerError)
					return
				} else {
					log.Println("called slack api successfully - timestamp: " + respTimestamp)
				}
			}
		}
	} else {
		log.Println("type is not handled: " + eventsAPIEvent.Type)
	}

	w.WriteHeader(http.StatusAccepted)
}

// HttpAdapter converts the lambda specific request and response objects into HTTP objects for use with the Handler function.
// This allows the app to be run as a regular webserver if needed, outside of lambda, and also more easily allows
// the slack signature to be verified, as the code in the slack api expects the HTTP objects.
func HttpAdapter(event events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {

	// read the body into a io reader - if its base64 encoded, decode it first
	var body []byte
	if event.IsBase64Encoded {
		b, err := base64.StdEncoding.DecodeString(event.Body)
		if err != nil {
			log.Println("base64 decoding failed")
			return events.LambdaFunctionURLResponse{StatusCode: http.StatusInternalServerError}, err
		}
		body = b
	} else {
		body = []byte(event.Body)
	}
	br := bytes.NewReader(body)

	requestHeaders := map[string][]string{}
	for k, v := range event.Headers {
		if k == "x-slack-signature" {
			k = "X-Slack-Signature" // this is dumb, but required. the slack verifier is case sensitive
		} else if k == "x-slack-request-timestamp" {
			k = "X-Slack-Request-Timestamp"
		}
		requestHeaders[k] = []string{v}
	}

	// create http request and response objects
	r := httptest.NewRequest(event.RequestContext.HTTP.Method, "/", br)
	r.Header = requestHeaders
	w := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(w, r)

	responseHeaders := map[string]string{}
	for k, v := range w.Header() {
		responseHeaders[k] = v[0]
	}

	// convert the http response into a lambda response
	respEvent := events.LambdaFunctionURLResponse{
		Headers:    responseHeaders,
		Body:       w.Body.String(),
		StatusCode: w.Code,
	}
	return respEvent, nil
}

func main() {
	http.HandleFunc("/", Handler)

	// setting this flag determines if the app will run as a webserver or lambda
	serveArg := flag.Int("serve", 0, "port to serve web on. if unspecified then the app will run expecting a lambda request/response")
	flag.Parse()
	if *serveArg > 0 {
		log.Println("listening on port " + strconv.Itoa(*serveArg))
		log.Println(http.ListenAndServe("0.0.0.0:"+strconv.Itoa(*serveArg), http.DefaultServeMux))
	} else {
		lambda.Start(HttpAdapter)
	}
}
