package parse

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"regexp"
)

var Config struct {
	Listen string
	L7     map[string]string
	Policy map[string]string
}

var RegExpMap map[string]*regexp.Regexp

func init() {
	loadConfig()
	InitRegExpMap()
}

func loadConfig() {
	log.Println("load config ...")
	buf, err := ioutil.ReadFile("config.json")
	if err != nil {
		panic("配置文件config.json载入失败:" + err.Error())
	}
	if err = json.Unmarshal(buf, &Config); err != nil {
		panic("配置文件config.json解析失败:" + err.Error())
	}
}

func InitRegExpMap() {
	RegExpMap = make(map[string]*regexp.Regexp)
	for prot, reg := range Config.L7 {
		RegExpMap[prot] = regexp.MustCompile(reg)
	}
}

func GetAddrByRegExp(testbuf []byte) (string, string) {
	for prot, regExp := range RegExpMap {
		if regExp.Match(testbuf) {
			return prot, Config.Policy[prot]
		}
	}
	return "default", Config.Policy["default"]

}
