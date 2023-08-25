package lzsigma

import (
	"io"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

type Logsource struct {
	Product string
	Service string
}
type Rule struct {
	Title          string
	Id             string
	Status         string
	Description    string
	Preferences    []string
	Author         string
	Date           string
	Modified       string
	Tags           []string
	Logsource      Logsource
	Detection      map[string]interface{}
	Falsepositives []string
	Level          string
}

type SigmaRule struct {
	Source string
}

func (sr *SigmaRule) content() []byte {

	data, err := http.Get(sr.Source)
	if err != nil {

		f, err := os.Open(sr.Source)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		cont, err := io.ReadAll(f)
		if err != nil {
			panic(err)
		}

		return cont
	}
	defer data.Body.Close()

	data_bytes, err := io.ReadAll(data.Body)
	if err != nil {
		panic(err)
	}
	return data_bytes
}

func (sr *SigmaRule) Parse() Rule {
	var rule Rule
	if err := yaml.Unmarshal(sr.content(), &rule); err != nil {
		panic(err)
	}

	return rule
}
