package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/hillu/go-yara/v4"
	"github.com/slack-go/slack/slackevents"
)

//go:embed rules/*
var rules embed.FS

var (
	signingSecret string
	scanner       yara.Scanner
)

const (
	slackSigningSecretEnvVar = "SLACK_SIGNING_SECRET"
	slackReqTimestampHeader  = "x-slack-request-timestamp"
	slackSignatureHeader     = "x-slack-signature"
)

func init() {
	signingSecret = os.Getenv(slackSigningSecretEnvVar)
	if signingSecret == "" {
		log.Fatal("Required environment variable(s) missing")
	}

	buildRules()
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

func scan(text string) (bool, string) {
	var m yara.MatchRules
	err := scanner.SetCallback(&m).ScanMem([]byte(text))
	if err != nil {
		log.Fatal(err)
	}

	if len(m) == 0 {
		return true, ""
	}

	buf := &bytes.Buffer{}
	for i, match := range m {
		if i > 0 {
			fmt.Fprint(buf, ", ")
		}
		fmt.Fprintf(buf, "%s:%s", match.Namespace, match.Rule)
	}

	return false, buf.String()
}

func serverError() events.LambdaFunctionURLResponse {
	return events.LambdaFunctionURLResponse{StatusCode: http.StatusInternalServerError}
}

func badRequest(text string) events.LambdaFunctionURLResponse {
	return events.LambdaFunctionURLResponse{StatusCode: http.StatusBadRequest, Body: text}
}

func Handler(r events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	log.Println("handler triggered")

	body, err := base64.StdEncoding.DecodeString(r.Body)
	if err != nil {
		log.Println("base64 decoding failed")
		return serverError(), nil
	}

	slackTimestamp := r.Headers[slackReqTimestampHeader]
	slackSignature := r.Headers[slackSignatureHeader]

	slackSigningBaseString := "v0:" + slackTimestamp + ":" + string(body)

	if !matchSignature(slackSignature, signingSecret, slackSigningBaseString) {
		return events.LambdaFunctionURLResponse{Body: "Function was not invoked by Slack", StatusCode: http.StatusForbidden}, nil
	}

	log.Println("slack signature verified")

	eventsAPIEvent, err := slackevents.ParseEvent(json.RawMessage(body), slackevents.OptionNoVerifyToken())
	if err != nil {
		return serverError(), nil
	}

	if eventsAPIEvent.Type == slackevents.URLVerification {
		log.Println("type is url verification message")

		var r *slackevents.ChallengeResponse
		err := json.Unmarshal([]byte(body), &r)
		if err != nil {
			return serverError(), nil
		}
		respHeader := map[string]string{"Content-Type": "text"}
		return events.LambdaFunctionURLResponse{StatusCode: 200, Headers: respHeader, Body: r.Challenge}, nil
	}

	if eventsAPIEvent.Type == string(slackevents.Message) {
		log.Println("type is message event")

		innerEvent := eventsAPIEvent.InnerEvent
		switch ev := innerEvent.Data.(type) {
		case *slackevents.MessageEvent:
			respHeader := map[string]string{"Content-Type": "text"}
			return events.LambdaFunctionURLResponse{StatusCode: 200, Headers: respHeader, Body: ev.Text}, nil
		}
	}

	return badRequest("not a valid event type: " + eventsAPIEvent.Type), nil
}

func matchSignature(slackSignature, signingSecret, slackSigningBaseString string) bool {

	//calculate SHA256 of the slackSigningBaseString using signingSecret
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(slackSigningBaseString))

	//hex encode the SHA256
	calculatedSignature := "v0=" + hex.EncodeToString(mac.Sum(nil))

	match := hmac.Equal([]byte(slackSignature), []byte(calculatedSignature))
	return match
}

func main() {
	lambda.Start(Handler)
}
