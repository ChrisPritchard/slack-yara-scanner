package main

import (
	"bytes"
	"embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/hillu/go-yara/v4"
)

//go:embed rules/*
var rules embed.FS
var scanner yara.Scanner

func main() {
	buildRules()

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	f, _ := os.Create("/var/log/golang/golang-server.log")
	defer f.Close()
	// log.SetOutput(f)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.NotFound(w, r)
		} else {
			fmt.Fprintf(w, "up, requested at %s", time.Now().Format(time.RFC1123))
		}
	})

	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.NotFound(w, r)
		} else {
			text := r.FormValue("text")
			fmt.Fprintf(w, "scanning '%s'\n", text)

			safe, matches := scan(text)
			if safe {
				fmt.Fprintf(w, "no bad strings found")
			} else {
				fmt.Fprintf(w, "%s", matches)
			}

		}
	})

	log.Printf("Listening on port %s\n\n", port)
	http.ListenAndServe(":"+port, nil)
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
