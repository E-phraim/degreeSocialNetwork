package main

import (
	"degreenetwork/api/api"
	"fmt"
)

func main(){
	api.Init()

	fmt.Println("Welcome to Degree Network API")
	api.StartServer()
}