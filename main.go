// zeaburTest project main.go
package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
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
	command := exec.CommandContext(ctx, "bash", strings.Split(cmd, " ")...)
	out, err := command.StdoutPipe()
	if err != nil {
		w.Header().Set("X-Err", "command out pip failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	reader := bufio.NewReaderSize(out, 4096)
	sent := int64(0)
	for {
		N, err := io.Copy(w, reader)
		if err != nil {
			if err != io.EOF && err != io.ErrClosedPipe {
				log.Println(uu, "copy exec outbuff failed", err)
			}
			cancel()
			break
		}
		sent += N
	}

	log.Println(uu, "request over, size:", sent)
}

func main() {
	secureKey = os.Getenv("SECURE_KEY")

	logFile, err := os.OpenFile("out.log", os.O_APPEND|os.O_CREATE, os.ModePerm)
	if err != nil {
		log.Fatalln(err)
	}

	log.SetOutput(logFile)
	http.HandleFunc("/", indexHandler)
	log.Fatal(http.ListenAndServe(":80", nil))
}
