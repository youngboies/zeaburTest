// zeaburTest project main.go
package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	secureKey string
)

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("index handler")
	u, err := uuid.NewRandom()
	if err != nil {
		log.Println("uuid create failed", err)
		w.Header().Set("X-Err", "uuid create failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	uu := u.String()
	w.Header().Set("X-Request-Id", uu)
	log.Println(uu, r.RequestURI, "start")

	args := r.URL.Query()
	cmd := args.Get("cmd")
	if len(secureKey) > 0 {
		key := args.Get("key")
		if len(key) <= 0 {
			w.Header().Set("X-Err", "auth failed")
			w.WriteHeader(http.StatusForbidden)
			return
		}

		expStr := args.Get("exp")
		exp, err := strconv.Atoi(expStr)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if int64(exp) > time.Now().Unix() {
			w.Header().Set("X-Err", "expire")
			w.WriteHeader(http.StatusForbidden)
			return
		}

		secureRet := md5.Sum([]byte(cmd + secureKey + expStr))
		if hex.EncodeToString(secureRet[:]) != key {
			w.Header().Set("X-Err", "auth failed")
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	if len(cmd) <= 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3600)
	command := exec.CommandContext(ctx, "/bin/bash", []string{"-c", cmds}...)
	out, err := command.StdoutPipe()
	if err != nil {
		log.Println(uu, "command out pip failed", err)
		w.Header().Set("X-Err", "command out pip failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	command.Stderr = os.Stdout
	defer out.Close()

	err = command.Start()
	if err != nil {
		log.Println(uu, "command run failed", err)
		w.Header().Set("X-Err", "command run failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sent := int64(0)
	buf := make([]byte, 4096)
	for {
		N, err := out.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Println(uu, "command read failed", err)
			}

			break
		}

		sent += N

		N, err = w.Write(buf[:N])
		if err != nil {
			if err != io.EOF {
				log.Println(uu, "http write failed", err)
			}

			break
		}
	}

	command.Wait()

	log.Println(uu, "request over, size:", sent)
}

func main() {
	secureKey = os.Getenv("SECURE_KEY")
	port := os.Getenv("PORT")
	envs := os.Environ()
	for _, val := range envs {
		fmt.Println(val)
	}

	fmt.Println("start process")

	logFile, err := os.OpenFile("out.log", os.O_APPEND|os.O_CREATE, os.ModePerm)
	if err != nil {
		log.Fatalln(err)
	}

	log.SetOutput(logFile)
	http.HandleFunc("/", indexHandler)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
