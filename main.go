package main

import (
	"flag"
	"net/http"
	"time"
	"os"
	"os/signal"
	"syscall"
	"fmt"
	"io"
	"bufio"
	"strings"
	"log"
	"bytes"

	"github.com/pkg/errors"
)

const (
	keyMagicComment = "synced from github"
)

func main() {
	var (
		syncInterval time.Duration
		disablePeriodicSync bool
		authorizedKeysFilePath string
		githubUsername string
	)

	flag.DurationVar(&syncInterval, "sync-interval", time.Minute, "interval to sync keys at")
	flag.BoolVar(&disablePeriodicSync, "disable-periodic-sync", false, "sync just once then exit")
	flag.StringVar(&authorizedKeysFilePath, "authorized-keys-path", os.Getenv("HOME") + "/.ssh/authorized_keys", "authorized_keys file to write keys into")
	flag.Parse()

	githubUsername = flag.Arg(0)
	if githubUsername == "" {
		fmt.Fprintln(os.Stderr, "sync-github-ssh-keys requires a github username as its first argument")
		flag.PrintDefaults()
		os.Exit(1)
	}


	if disablePeriodicSync {
		err := syncGithubKeys(githubUsername, authorizedKeysFilePath)
		if err != nil {
			log.Printf("sync failed: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	doSync := make(chan bool, 1)
	doSync <- true

	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			doSync <- true
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		<-c
		doSync <- true
	}()

	for range doSync {
		err := syncGithubKeys(githubUsername, authorizedKeysFilePath)
		if err != nil {
			log.Printf("sync failed: %v", err)
		}
	}
}

func syncGithubKeys(githubUsername string, authorizedKeysFilePath string) error {
	publicKeys, err := getSSHKeys(githubUsername)
	if err != nil {
		return errors.Wrap(err, "could not get public keys from github")
	}

	authorizedKeysFile, err := os.OpenFile(authorizedKeysFilePath, os.O_RDWR, 0644)
	if err != nil {
		return errors.Wrap(err, "could not open authorized keys file")
	}
	defer authorizedKeysFile.Close()

	outputBuffer := bytes.NewBuffer(nil)
	err = ensureKeysetUpToDate(publicKeys, outputBuffer, authorizedKeysFile)
	if err != nil {
		return errors.Wrap(err, "could not update authorized keys file")
	}

	_, err = authorizedKeysFile.Seek(0, 0)
	if err != nil {
		return errors.Wrap(err, "could not seek authorized keys file")
	}

	n, err := io.Copy(authorizedKeysFile, outputBuffer)
	if err != nil {
		return errors.Wrap(err, "could not copy new contents to authorized keys file")
	}

	err = authorizedKeysFile.Truncate(n)
	if err != nil {
		return errors.Wrap(err, "could not truncate authorized keys file")
	}
	
	return nil
}

func ensureKeysetUpToDate(newKeyset []string,  output io.Writer, input io.Reader) error {
	newKeysetHashed := map[string]struct{}{}
	for _, key := range newKeyset {
		newKeysetHashed[key] = struct{}{}
	}

	bufferedInput := bufio.NewReader(input)
	for i := 1; ; i++ {
		line, err := bufferedInput.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "could not read authorized keys file")
		}
		if len(line) != 0 && line[len(line) - 1] == '\n' {
			line = line[:len(line)-1]
		}

		// the last component of the lines in an authorized keys file must be
		// stripped off before comparison with the github provided keys
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			return errors.Errorf("line %v in authorized keys file malformed", i)
		}

		key := parts[0] + " " + parts[1]

		// Check to see if the key was created by us
		if len(parts) > 3 && parts[2] == keyMagicComment {
			// if it's still in the set of keys, then write it out again
			if _, ok := newKeysetHashed[key]; !ok {
				_, err := fmt.Fprintf(output, "%v %v\n", key, keyMagicComment)
				if err != nil {
					return errors.Wrap(err, "could not write out existing synced key")
				}
			} else {
				log.Printf("removing key: %v", key)
			}
		} else {
			_, err := fmt.Fprintln(output, line)
			if err != nil {
				return errors.Wrap(err, "could not write out existing unsynced key")
			}
		}

		delete(newKeysetHashed, key)
	}

	for key := range newKeysetHashed {
		log.Printf("adding key: %v", key)
		_, err := fmt.Fprintf(output, "%v %v\n", key, keyMagicComment)
		if err != nil {
			return errors.Wrap(err, "could not write out new key")
		}
	}

	return nil
}

func getSSHKeys(githubUsername string) ([]string, error) {
	url := fmt.Sprintf("https://github.com/%v.keys", githubUsername)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct request")
	}

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, errors.Wrap(err, "could not make request")
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.Errorf("invalid status code: %v", resp.StatusCode)
	}

	publicKeys := []string{}
	buf := bufio.NewReader(resp.Body)
	for {
		publicKey, err := buf.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "failed to read response body")
		}

		publicKeys = append(publicKeys, publicKey[:len(publicKey)-1])
	}

	return publicKeys, nil
}