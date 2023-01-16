// Package main implements a TURN server with a
// specified port range.
package main

import (
	"github.com/pion/turn/v2"
	allocation2 "github.com/pion/turn/v2/internal/util"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	port := 3478

	// Create a UDP listener to pass into pion/turn
	// pion/turn itself doesn't allocate any UDP sockets, but lets the user pass them in
	// this allows us to add logging, storage or modify inbound/outbound traffic
	udpListener, err := net.ListenPacket("udp4", "0.0.0.0:"+strconv.Itoa(port))
	if err != nil {
		log.Panicf("Failed to create TURN server listener: %s", err)
	}

	authHandler := turnAuthHandler("")

	s, err := turn.NewServer(turn.ServerConfig{
		Realm: "zocks", // Set AuthHandler callback
		// This is called every time a user tries to authenticate with the TURN server
		// Return the key for that user, or false when no user is found
		AuthHandler: authHandler,
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
					PublicRelayAddress:  net.ParseIP("3.125.153.109"),
					PrivateRelayAddress: net.ParseIP("172.31.8.56"),
					RelayAddress:        nil,
					Address:             "0.0.0.0",
					MinPort:             50000,
					MaxPort:             55000,
				},
			},
		},
	})
	if err != nil {
		log.Panic(err)
	}

	// Block until user sends SIGINT or SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	if err = s.Close(); err != nil {
		log.Panic(err)
	}
}

func turnAuthHandler(authKey string) turn.AuthHandler {
	return func(username string, realm string, srcAddr net.Addr) (key []byte, relayAddressType allocation2.RelayAddressType, ok bool) {
		values := strings.Split(username, ":")
		//timestamp := values[0]
		//t, err := strconv.Atoi(timestamp)
		//if err != nil {
		//	log.Println("Invalid time-windowed username %q", username)
		//	return nil, allocation2.PublicRelay, false
		//}
		//if int64(t) < time.Now().Unix() {
		//	log.Println("Expired time-windowed username %q", username)
		//	return nil, allocation2.PublicRelay, false
		//}
		//
		//mac := hmac.New(sha256.New, []byte(authKey))
		//mac.Write([]byte(username))
		//sum := mac.Sum(nil)
		//password := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum)))
		rat := allocation2.PublicRelay
		if len(values) > 2 {
			addressType, _ := strconv.Atoi(values[2])
			rat = getRelayAddressType(addressType)
		}

		return turn.GenerateAuthKey(username, realm, "password"), rat, true
	}
}

func getRelayAddressType(addressType int) allocation2.RelayAddressType {
	relayAddressType := allocation2.RelayAddressType(addressType)
	if relayAddressType == allocation2.PrivateRelay {
		return allocation2.PrivateRelay
	} else {
		return allocation2.PublicRelay
	}
}
