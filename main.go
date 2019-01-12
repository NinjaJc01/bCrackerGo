package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	channelPwds chan string
	channelRes  chan bool
	channelFin  chan string
	hash        string
)

type pwList struct {
	Pws []string `json:"passwords"`
}
type hashStruct struct {
	Hash string `json:"hash"`
}

func main() {
	var possiblePws pwList
	var hashRead hashStruct
	jsonFile, err := os.Open("passwords.json")
	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal([]byte(byteValue), &possiblePws)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully Opened passwords.json")
	jsonFile, err = os.Open("hash.json")
	byteValue, _ = ioutil.ReadAll(jsonFile)
	json.Unmarshal([]byte(byteValue), &hashRead)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully Opened hash.json")
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	//hash = hashAndSalt([]byte("admin"))
	hash = hashRead.Hash
	fmt.Println(hash)
	channelPwds = make(chan string, len(possiblePws.Pws))
	channelFin = make(chan string, 1)
	//channelRes = make(chan bool, len(possiblePws.Pws))
	start := time.Now()
	fmt.Println("Starting")
	fmt.Print("[")
	for _, pw := range possiblePws.Pws {
		channelPwds <- pw
		go crackBcrypt()
	}
	fmt.Println("\nPW: " + <-channelFin +fmt.Sprintf("\nRun Time: %v\n", time.Now().Sub(start)))
}

func crackBcrypt() {
	guess := <-channelPwds
	//fmt.Println(len(channelPwds))
	if len(channelFin) == 0 {
		val := comparePasswordsBcrypt(hash, []byte(guess))
		//channelRes <- val
		if val {
			fmt.Print(" ]")
			channelFin <- guess
		} else {
			fmt.Print("█")
			//channelRes <- false
		}
	}
}
func comparePasswordsBcrypt(hashedPwd string, plainPwd []byte) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		//fmt.Println(err)
		return false
	}

	return true
}
