package main

import (
	"bufio"
	"log"
	"os"
	"os/user"
)

type PasswdDict struct {
	f     *os.File
	w     *bufio.Writer
	uMaps map[string]struct{}
}

func NewPasswdDict(Users []string) *PasswdDict {
	Pd := &PasswdDict{}

	file, err := os.OpenFile("dictionary.txt", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0640)
	if err != nil {
		log.Fatal(err)
	}

	Pd.f = file
	Pd.w = bufio.NewWriter(Pd.f)
	Pd.uMaps = make(map[string]struct{})
	for _, value := range Users {
		_, err := user.Lookup(value)
		if err != nil {
			continue
		}
		Pd.uMaps[value] = struct{}{}
	}
	// log.Printf("Final Users: %v", Pd.uMaps)
	return Pd
}

func (pd *PasswdDict) WritePair(user string, password string) {
	if _, ok := pd.uMaps[user]; !ok {
		return
	}
	str := user + ":" + password + "\n"
	length := len(str)
	if length >= pd.w.Available() {
		err := pd.w.Flush()
		if err != nil {
			log.Printf("Flush PasswdDict: %s\n", err)
		}
	}
	_, err := pd.w.WriteString(str)
	if err != nil {
		log.Printf("WriteString to PasswdDict: %s\n", err)
	}
	return
}

func (pd *PasswdDict) Close() {
	pd.w.Flush()
	pd.f.Close()
}
