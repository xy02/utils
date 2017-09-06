package utils

import (
	"encoding/json"
	"log"
	"testing"
)

type Person interface {
	Hello() string
}

type Chinese struct{ name string }

func (p Chinese) Hello() string {
	return "你好，我是" + p.name
}

type American struct{ age int }

func (p American) Hello() string {
	return "Hello,I'm " + string(p.age)
}

func TestUnmarshal(t *testing.T) {
	str := `{"name":"张三"}`
	var person Person = Chinese{}
	err := json.Unmarshal([]byte(str), person)
	if err != nil {
		t.Error(err)
	} else {
		log.Println(person.Hello())
	}
}
